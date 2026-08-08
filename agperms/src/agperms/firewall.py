"""The public entry point: :class:`Firewall`.

Everything a caller needs is a method here. The engines underneath
(:mod:`agperms._tokens`, :mod:`agperms._audit`, :mod:`agperms._guardrails`) are
private because their boundaries are an implementation detail that should be free
to move.
"""

from __future__ import annotations

import datetime as _dt
import logging
import time
import uuid
from contextlib import contextmanager
from typing import Iterator

from agperms._audit import AuditEvent, AuditLog
from agperms._guardrails import (
    AnomalyDetector,
    CircuitBreaker,
    CircuitState,
    RateLimiter,
    SlidingWindowCache,
)
from agperms._time import (
    as_utc,
    from_ts,
    hash_identifier,
    iso,
    truncate_reason,
    utcnow,
    utcnow_ts,
)
from agperms._tokens import TokenEngine
from agperms.config import Config
from agperms.errors import (
    REASON_EXPIRED,
    REASON_MISSING_TOKEN,
    REASON_REVOKED,
    REASON_SCOPE_NOT_GRANTED,
    ApprovalRequired,
    DepthLimitExceeded,
    Denied,
    ParentTokenInvalid,
    RootChainBroken,
    ScopeEscalationDenied,
    TokenError,
)
from agperms.models import (
    ActionRecord,
    ActionReview,
    Capability,
    ChainHop,
    CompletionState,
    IntegrityReport,
    PendingApproval,
    RevocationResult,
    Reversibility,
    TokenClaims,
    TokenMetadata,
    VerifyResult,
)
from agperms.storage.memory import MemoryStorage
from agperms.storage.protocol import Storage

logger = logging.getLogger(__name__)


class ActionHandle:
    """Handle yielded by :meth:`Firewall.action`.

    Exposes the ids a caller might want to correlate against their own logs, and
    lets a caller attach a note describing what the action actually did.
    """

    __slots__ = ("action_id", "jti", "name", "scope", "reversibility", "_notes")

    def __init__(
        self,
        action_id: str,
        jti: str,
        name: str,
        scope: str,
        reversibility: Reversibility = Reversibility.IRREVERSIBLE,
    ) -> None:
        self.action_id = action_id
        self.jti = jti
        self.name = name
        self.scope = scope
        self.reversibility = reversibility
        self._notes: list[str] = []

    def note(self, text: str) -> None:
        """Attach a short note, recorded when the action closes."""
        self._notes.append(truncate_reason(text))

    @property
    def notes(self) -> list[str]:
        return list(self._notes)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ActionHandle(name={self.name!r}, action_id={self.action_id[:8]}…)"


class Firewall:
    """Capability narrowing, revocation and in-flight forensics.

    The default construction needs nothing::

        fw = Firewall()
        root = fw.mint_root(subject="human:alice", scopes=["read_calendar"])

    That gives you an ephemeral signing key and in-memory storage, which is right
    for tests and single-process embedding and wrong for anything that must
    survive a restart -- pass a durable ``storage`` and a fixed
    ``Config.jwt_secret`` for that.
    """

    def __init__(
        self,
        *,
        config: Config | None = None,
        storage: Storage | None = None,
        rate_limit_cache: SlidingWindowCache | None = None,
    ) -> None:
        self.config = config or Config()
        self.storage: Storage = storage or MemoryStorage()
        self._tokens = TokenEngine(self.config)
        self._audit = AuditLog(self.storage)
        self._rate = RateLimiter(self.config, rate_limit_cache)
        self._circuit = CircuitBreaker(self.config)
        self._anomaly = AnomalyDetector(self.config)

        # Audit the breaker tripping, without the breaker knowing what an audit
        # log is.
        self._circuit.set_open_callback(
            lambda reason: self._audit.log(
                AuditEvent(
                    action="circuit_opened",
                    decision="deny",
                    reason=truncate_reason(reason),
                )
            )
        )

        if not getattr(self.storage, "durable", False):
            logger.info(
                "agperms is using non-durable storage: revocations will not "
                "survive this process. Pass a durable Storage for production."
            )

    # ==================================================================
    # Minting
    # ==================================================================
    def mint_root(
        self,
        *,
        subject: str,
        scopes: list[str],
        ttl_seconds: int | None = None,
        max_depth: int | None = None,
    ) -> Capability:
        """Mint a depth-0 capability for a human principal.

        ``subject`` is a real identifier (a username, an email). It is hashed
        before anything is persisted and never appears in the token, which
        carries an opaque ``human:<uuid>`` instead.
        """
        if not scopes:
            raise ValueError("a root capability with no scopes grants nothing")

        ttl = min(
            ttl_seconds or self.config.default_ttl_seconds,
            self.config.max_ttl_seconds,
        )
        depth_ceiling = max_depth or self.config.max_delegation_depth
        if depth_ceiling < 1:
            raise ValueError("max_depth must be >= 1")

        subject_record = self._resolve_subject(subject, "human")
        minted = self._tokens.mint_root(
            subject_id=subject_record.subject_id,
            scopes=scopes,
            ttl_seconds=ttl,
            max_depth=depth_ceiling,
        )
        self._persist_token(minted, parent_jti=None)
        self._audit.log(
            AuditEvent(
                action="root_minted",
                actor_id=subject_record.subject_id,
                actor_hash=subject_record.identifier_hash,
                jti=minted.jti,
                root_jti=minted.jti,
                scopes=list(minted.claims.scopes),
                depth=0,
                decision="allow",
                detail={"ttl_seconds": ttl, "max_depth": depth_ceiling},
            )
        )
        return minted

    def delegate(
        self,
        parent_token: str,
        *,
        to: str,
        scopes: list[str],
        ttl_seconds: int | None = None,
    ) -> Capability:
        """Mint a narrower capability for a sub-agent.

        Raises :class:`~agperms.errors.ScopeEscalationDenied` if ``scopes`` is not
        a subset of what ``parent_token`` actually holds, and
        :class:`~agperms.errors.ApprovalRequired` if any requested scope is
        sensitive -- in which case nothing is minted until a human approves.
        """
        self._circuit.check()

        if not scopes:
            raise ValueError("a delegation with no scopes grants nothing")

        parent = self._decode_live(parent_token)
        self._rate.check(parent.sub, "delegate")
        self._assert_root_alive(parent)

        requested = sorted(set(scopes))

        # The invariant this library exists for. Checked against the freshly
        # decoded parent, never a cached record or the caller's own claim.
        denied = [s for s in requested if s not in parent.scope_set]
        if denied:
            self._audit.log(
                AuditEvent(
                    action="escalation_denied",
                    actor_id=parent.sub,
                    parent_jti=parent.jti,
                    root_jti=parent.root_jti,
                    scopes=requested,
                    denied_scopes=denied,
                    decision="deny",
                    reason="requested scopes exceed the parent grant",
                    depth=parent.depth + 1,
                    detail={"child_agent_id": to},
                )
            )
            self._circuit.record(error=True, subject_id=parent.sub, policy_denial=True)
            raise ScopeEscalationDenied(
                requested=requested,
                allowed_max=sorted(parent.scope_set),
                denied_scopes=denied,
            )

        child_depth = parent.depth + 1
        if child_depth > parent.max_depth:
            self._audit.log(
                AuditEvent(
                    action="depth_limit_exceeded",
                    actor_id=parent.sub,
                    parent_jti=parent.jti,
                    root_jti=parent.root_jti,
                    scopes=requested,
                    decision="deny",
                    reason=f"depth {child_depth} exceeds max_depth {parent.max_depth}",
                    depth=child_depth,
                    detail={"child_agent_id": to},
                )
            )
            self._circuit.record(error=True, subject_id=parent.sub, policy_denial=True)
            raise DepthLimitExceeded(child_depth, parent.max_depth)

        finding = self._anomaly.observe_delegation(parent.sub, len(requested))
        if finding:
            self._audit.log(
                AuditEvent(
                    action="anomaly_flagged",
                    actor_id=parent.sub,
                    parent_jti=parent.jti,
                    root_jti=parent.root_jti,
                    scopes=requested,
                    decision="flag",
                    reason=truncate_reason(finding),
                    detail={"child_agent_id": to, "auto_blocked": False},
                )
            )

        # The one place a child's expiry is decided.
        requested_ttl = ttl_seconds or self.config.default_ttl_seconds
        child_exp = min(utcnow_ts() + requested_ttl, parent.exp)

        sensitive = self.config.sensitive_subset(requested)
        if sensitive:
            approval = self._park_for_approval(
                parent=parent,
                child_agent_id=to,
                requested_scopes=requested,
                ttl_seconds=requested_ttl,
                sensitive=sensitive,
            )
            self._circuit.record(error=False, subject_id=parent.sub)
            raise ApprovalRequired(
                approval_id=approval.approval_id,
                requested_scopes=requested,
                sensitive_scopes=sensitive,
            )

        child_subject = self._resolve_subject(to, "agent")
        minted = self._tokens.mint_child(
            parent=parent,
            child_subject_id=child_subject.subject_id,
            scopes=requested,
            exp=child_exp,
        )
        self._persist_token(minted, parent_jti=parent.jti)
        self.storage.add_edge(parent.jti, minted.jti)
        self._audit.log(
            AuditEvent(
                action="delegated",
                actor_id=parent.sub,
                jti=minted.jti,
                parent_jti=parent.jti,
                root_jti=minted.claims.root_jti,
                scopes=list(minted.claims.scopes),
                decision="allow",
                depth=minted.claims.depth,
                detail={
                    "child_agent_id": to,
                    "child_subject_id": child_subject.subject_id,
                    "exp": minted.claims.exp,
                },
            )
        )
        self._circuit.record(error=False, subject_id=parent.sub)
        return minted

    # ==================================================================
    # Verification
    # ==================================================================
    def verify(self, token: str | None, required_scope: str) -> VerifyResult:
        """Check a capability against a required scope.

        Order matters: the breaker reads nothing from the token, then the
        signature is established, and only then is any claim trusted.
        """
        started = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000.0

        if self._circuit.is_open():
            return VerifyResult(
                valid=False, reason="circuit_open", latency_ms=elapsed()
            )

        if not token:
            return VerifyResult(
                valid=False, reason=REASON_MISSING_TOKEN, latency_ms=elapsed()
            )

        # Signature, issuer and required claims. Expiry checked separately below
        # so "expired" and "forged" stay distinguishable.
        try:
            claims = self._tokens.decode(token, verify_exp=False)
        except TokenError as exc:
            # A forged or malformed token is a client error, not a system fault:
            # counting it would let anyone open the breaker by posting garbage.
            self._circuit.record(error=True, policy_denial=True)
            self._audit.log(
                AuditEvent(
                    action="verify_denied",
                    required_scope=required_scope,
                    decision="deny",
                    reason=exc.reason,
                )
            )
            return VerifyResult(valid=False, reason=exc.reason, latency_ms=elapsed())

        def deny(reason: str) -> VerifyResult:
            self._circuit.record(
                error=True, subject_id=claims.sub, policy_denial=True
            )
            self._audit.log(
                AuditEvent(
                    action="verify_denied",
                    actor_id=claims.sub,
                    jti=claims.jti,
                    root_jti=claims.root_jti,
                    required_scope=required_scope,
                    scopes=list(claims.scopes),
                    decision="deny",
                    reason=reason,
                    depth=claims.depth,
                )
            )
            return VerifyResult(
                valid=False, reason=reason, claims=claims, latency_ms=elapsed()
            )

        # Keyed on the authenticated subject, so a forged token cannot spend a
        # real agent's budget.
        self._rate.check(claims.sub, "verify")

        if claims.exp < utcnow_ts():
            return deny(REASON_EXPIRED)

        if self.storage.is_revoked(claims.jti):
            return deny(REASON_REVOKED)
        # Every ancestor too: revoking a parent must kill descendants even if an
        # edge was never recorded.
        for ancestor in claims.ancestor_jtis:
            if self.storage.is_revoked(ancestor):
                return deny(REASON_REVOKED)

        if required_scope not in claims.scope_set:
            return deny(REASON_SCOPE_NOT_GRANTED)

        self._circuit.record(error=False, subject_id=claims.sub)
        latency = elapsed()
        self._audit.log(
            AuditEvent(
                action="verify_allowed",
                actor_id=claims.sub,
                jti=claims.jti,
                root_jti=claims.root_jti,
                required_scope=required_scope,
                scopes=list(claims.scopes),
                decision="allow",
                depth=claims.depth,
                latency_ms=latency,
            )
        )
        return VerifyResult(valid=True, claims=claims, latency_ms=latency)

    def require(self, token: str | None, required_scope: str) -> TokenClaims:
        """Like :meth:`verify` but raises :class:`~agperms.errors.Denied`."""
        result = self.verify(token, required_scope)
        if not result.valid:
            raise Denied(result.reason or "denied", required_scope=required_scope)
        assert result.claims is not None
        return result.claims

    # ==================================================================
    # In-flight actions
    # ==================================================================
    @contextmanager
    def action(
        self,
        token: str,
        *,
        scope: str,
        name: str,
        reversibility: Reversibility | None = None,
    ) -> Iterator[ActionHandle]:
        """Declare a side-effecting action so a revoke can classify it.

        ::

            with fw.action(token, scope="send_email", name="welcome_email"):
                send_email(draft)

        Verifies ``scope`` on entry, so an already-revoked token cannot open an
        action at all. Records that the action opened, then records whether it
        finished cleanly or raised.

        ``reversibility`` defaults to whatever ``Config.scope_reversibility`` says
        about ``scope`` (IRREVERSIBLE if the scope is unclassified). Pass it
        explicitly for the case where one scope covers both a recoverable and an
        unrecoverable path -- a soft delete and a hard delete under one
        ``delete_data`` grant.

        **This does not stop or interrupt anything.** It cannot: the library has
        no way to halt code already running in your process. What it buys you is
        knowledge -- if this token is revoked while the block is open, the revoke
        reports ``PARTIAL``/``UNKNOWN`` instead of silently having no idea. Any
        exception is re-raised unchanged.
        """
        claims = self.require(token, scope)
        self._rate.check(claims.sub, "action")

        resolved_reversibility = (
            reversibility
            if reversibility is not None
            else self.config.reversibility_of(scope)
        )

        action_id = str(uuid.uuid4())
        started_at = utcnow()
        record = ActionRecord(
            action_id=action_id,
            jti=claims.jti,
            subject_id=claims.sub,
            name=name,
            scope=scope,
            started_at=started_at,
            reversibility=resolved_reversibility,
        )
        self.storage.put_action(record)
        # Synchronous on purpose: the *absence* of this row is what a revoke
        # reads as "nothing was in flight", so it must be durable before the
        # guarded code runs.
        self._audit.log(
            AuditEvent(
                action="action_started",
                actor_id=claims.sub,
                jti=claims.jti,
                root_jti=claims.root_jti,
                required_scope=scope,
                decision="allow",
                depth=claims.depth,
                detail={
                    "action_id": action_id,
                    "action_name": name,
                    "reversibility": resolved_reversibility.value,
                },
            )
        )

        handle = ActionHandle(
            action_id, claims.jti, name, scope, resolved_reversibility
        )
        try:
            yield handle
        except BaseException as exc:
            # We know it started and did not finish: PARTIAL, not UNKNOWN.
            # UNKNOWN is reserved for the case where no exit path ran at all.
            self._close_action(
                handle,
                claims=claims,
                state=CompletionState.PARTIAL,
                failure_reason=truncate_reason(f"{type(exc).__name__}: {exc}"),
            )
            raise
        else:
            self._close_action(
                handle, claims=claims, state=CompletionState.CLEAN, failure_reason=None
            )

    def _close_action(
        self,
        handle: ActionHandle,
        *,
        claims: TokenClaims,
        state: CompletionState,
        failure_reason: str | None,
    ) -> None:
        finished_at = utcnow()
        self.storage.close_action(
            handle.action_id,
            state=state,
            finished_at=finished_at,
            failure_reason=failure_reason,
        )
        detail: dict[str, object] = {
            "action_id": handle.action_id,
            "action_name": handle.name,
            "completion_state": state.value,
            "reversibility": handle.reversibility.value,
        }
        if handle.notes:
            detail["notes"] = handle.notes
        self._audit.log(
            AuditEvent(
                action="action_completed" if state is CompletionState.CLEAN else "action_failed",
                actor_id=claims.sub,
                jti=claims.jti,
                root_jti=claims.root_jti,
                required_scope=handle.scope,
                decision="clean" if state is CompletionState.CLEAN else "partial",
                reason=failure_reason,
                depth=claims.depth,
                detail=detail,
            )
        )

    # ==================================================================
    # Revocation
    # ==================================================================
    def revoke(self, jti: str, *, reason: str | None = None) -> RevocationResult:
        """Revoke a capability and everything delegated from it.

        Also classifies any action that was still open on a revoked token, so the
        caller learns what was mid-flight rather than only that the token stopped
        working.
        """
        started = time.perf_counter()
        targets = self.storage.descendants_breadth_first(jti)
        revoked_at = utcnow()

        # Gather before revoking so an action that closes during this call is
        # judged against the state that prompted the revoke.
        candidates = self.storage.actions_for_review(targets)

        self.storage.revoke_many(
            targets,
            root_of_revocation=jti,
            reason=truncate_reason(reason) if reason else None,
            revoked_at=revoked_at,
        )

        reviews = self._queue_reviews(
            candidates, revoked_at=revoked_at, revocation_root_jti=jti
        )
        latency = (time.perf_counter() - started) * 1000.0

        self._audit.log(
            AuditEvent(
                action="revoked",
                jti=jti,
                decision="revoke",
                reason=truncate_reason(reason) if reason else None,
                latency_ms=latency,
                detail={
                    "subtree_count": len(targets),
                    "revoked_jtis": targets,
                    "actions_reviewed": len(candidates),
                    "reviews_queued": [r.review_id for r in reviews],
                },
            )
        )
        return RevocationResult(
            revoked_jtis=tuple(targets),
            latency_ms=latency,
            reviews=tuple(reviews),
        )

    def _queue_reviews(
        self,
        candidates: list[ActionRecord],
        *,
        revoked_at: _dt.datetime,
        revocation_root_jti: str,
    ) -> list[ActionReview]:
        """Record a review for each action that needs a human look."""
        # A repeat revoke of the same subtree must not duplicate reviews.
        already = {
            review.action_id for review in self.storage.list_reviews()
        }
        queued: list[ActionReview] = []
        for action in candidates:
            if action.action_id in already:
                continue
            classification = classify_action(action)
            if not classification.needs_human_review():
                continue
            review = ActionReview(
                review_id=str(uuid.uuid4()),
                jti=action.jti,
                action_id=action.action_id,
                action_name=action.name,
                classification=classification,
                revoked_at=revoked_at,
                revocation_root_jti=revocation_root_jti,
            )
            self.storage.put_review(review)
            self._audit.log(
                AuditEvent(
                    action="review_queued",
                    actor_id=action.subject_id,
                    jti=action.jti,
                    required_scope=action.scope,
                    decision="flag",
                    reason=f"action needs review at revocation: {classification.value}",
                    detail={
                        "review_id": review.review_id,
                        "action_id": action.action_id,
                        "action_name": action.name,
                        "completion_state": classification.value,
                        "reversibility": action.reversibility.value,
                        "review_priority": review_priority(action),
                    },
                )
            )
            queued.append(review)
        return queued

    # ==================================================================
    # Review queue
    # ==================================================================
    def pending_reviews(
        self,
        *,
        include_resolved: bool = False,
        order_by_priority: bool = False,
    ) -> list[ActionReview]:
        """Actions that were mid-flight when their capability was revoked.

        With ``order_by_priority``, the most urgent come first: UNKNOWN outranks
        PARTIAL, and within a completion state a less recoverable action outranks
        a more recoverable one. An UNKNOWN funds transfer should not be buried
        under a page of UNKNOWN idempotent reads.
        """
        if include_resolved:
            reviews = self.storage.list_reviews()
        else:
            reviews = self.storage.list_reviews(reviewed=False)
        if not order_by_priority:
            return reviews

        def priority(review: ActionReview) -> tuple[int, int]:
            action = self.storage.get_action(review.action_id)
            # A review whose action row has gone missing keeps its recorded
            # classification but loses reversibility detail; rank it worst-case
            # rather than dropping it to the bottom of the queue.
            reversibility = (
                action.reversibility
                if action is not None
                else Reversibility.IRREVERSIBLE
            )
            return (
                _COMPLETION_URGENCY[review.classification],
                reversibility.rank,
            )

        return sorted(reviews, key=priority, reverse=True)

    def resolve_review(
        self, review_id: str, *, note: str, reviewed_by: str
    ) -> ActionReview:
        """Close a review with a human's finding.

        The note is written into the hash-chained audit log, not just onto the
        review row: the row is a lookup cache, the chain is the evidence. This
        does not un-revoke anything -- it records a conclusion.
        """
        if not note.strip():
            raise ValueError("a review note is required; it is the evidentiary record")

        existing = self.storage.get_review(review_id)
        if existing is None:
            raise KeyError(f"unknown review {review_id}")
        if existing.reviewed:
            raise ValueError(f"review {review_id} is already resolved")

        resolved_at = utcnow()
        updated = ActionReview(
            review_id=existing.review_id,
            jti=existing.jti,
            action_id=existing.action_id,
            action_name=existing.action_name,
            classification=existing.classification,
            revoked_at=existing.revoked_at,
            revocation_root_jti=existing.revocation_root_jti,
            reviewed=True,
            reviewed_by=reviewed_by,
            reviewed_at=resolved_at,
        )
        self.storage.update_review(updated)
        self._audit.log(
            AuditEvent(
                action="review_resolved",
                actor_id=reviewed_by,
                jti=existing.jti,
                decision="reviewed",
                reason=truncate_reason(note),
                detail={
                    "review_id": existing.review_id,
                    "action_id": existing.action_id,
                    "action_name": existing.action_name,
                    "completion_state": existing.classification.value,
                    "note": truncate_reason(note),
                    "reviewed_by": reviewed_by,
                },
            )
        )
        return updated

    # ==================================================================
    # Approval gate
    # ==================================================================
    def approve(self, approval_id: str, *, approver: str) -> Capability:
        """Approve a parked delegation and mint the child capability here.

        The parent is re-validated now, not trusted from request time: it may have
        been revoked or expired while the request sat in the queue.
        """
        record = self._load_pending(approval_id)

        parent_meta = self.storage.get_token(record.parent_jti)
        if parent_meta is None:
            raise RootChainBroken("parent token record not found")

        if self.storage.is_revoked(record.parent_jti):
            self._decide_approval(record, status="denied", approver=approver)
            self._audit.log(
                AuditEvent(
                    action="approval_rejected",
                    actor_id=approver,
                    parent_jti=record.parent_jti,
                    decision="deny",
                    reason="parent was revoked while approval was pending",
                    detail={"approval_id": approval_id},
                )
            )
            raise ParentTokenInvalid(REASON_REVOKED)

        if record.parent_exp < utcnow_ts():
            self._decide_approval(record, status="expired", approver=approver)
            raise ParentTokenInvalid(REASON_EXPIRED)

        parent_claims = self._claims_from_metadata(parent_meta)
        # Clamped against the snapshotted parent_exp, not a fresh read, so a slow
        # approval cannot quietly extend the child's life.
        child_exp = min(utcnow_ts() + record.ttl_seconds, record.parent_exp)

        minted = self._tokens.mint_child(
            parent=parent_claims,
            child_subject_id=record.child_subject_id,
            scopes=list(record.requested_scopes),
            exp=child_exp,
            approval_required=True,
            approved_by=approver,
        )
        self._persist_token(minted, parent_jti=record.parent_jti)
        self.storage.add_edge(record.parent_jti, minted.jti)
        self._decide_approval(
            record,
            status="approved",
            approver=approver,
            child_jti=minted.jti,
            child_token=minted.token,
        )
        self._audit.log(
            AuditEvent(
                action="approval_granted",
                actor_id=approver,
                jti=minted.jti,
                parent_jti=record.parent_jti,
                root_jti=minted.claims.root_jti,
                scopes=list(minted.claims.scopes),
                decision="allow",
                depth=minted.claims.depth,
                detail={
                    "approval_id": approval_id,
                    "child_agent_id": record.child_agent_id,
                    "sensitive_scopes": list(record.sensitive_scopes),
                },
            )
        )
        return minted

    def deny(self, approval_id: str, *, approver: str, reason: str | None = None) -> None:
        """Deny a parked delegation. Nothing is ever minted."""
        record = self._load_pending(approval_id)
        self._decide_approval(record, status="denied", approver=approver)
        self._audit.log(
            AuditEvent(
                action="approval_denied",
                actor_id=approver,
                parent_jti=record.parent_jti,
                scopes=list(record.requested_scopes),
                decision="deny",
                reason=truncate_reason(reason) if reason else "denied by human",
                detail={
                    "approval_id": approval_id,
                    "child_agent_id": record.child_agent_id,
                },
            )
        )

    def collect(self, approval_id: str) -> Capability | None:
        """Collect an approved capability. ``None`` while still pending."""
        record = self.storage.get_approval(approval_id)
        if record is None:
            raise KeyError(f"unknown approval {approval_id}")
        if record.status != "approved" or not record.child_token:
            if record.status in {"denied", "expired"}:
                raise Denied(
                    f"approval_{record.status}", approval_id=approval_id
                )
            return None
        claims = self._tokens.decode(record.child_token, verify_exp=False)
        if not record.collected:
            self.storage.update_approval(
                PendingApproval(**{**record.__dict__, "collected": True})
                if hasattr(record, "__dict__")
                else record
            )
        return Capability(token=record.child_token, claims=claims)

    def pending_approvals(self) -> list[PendingApproval]:
        self.expire_stale_approvals()
        return self.storage.list_approvals(status="pending")

    def expire_stale_approvals(self) -> int:
        """Mark timed-out approval requests expired. Returns how many."""
        now = utcnow()
        count = 0
        for record in self.storage.list_approvals(status="pending"):
            expires = as_utc(record.expires_at)
            assert expires is not None
            if expires < now:
                self._decide_approval(record, status="expired", approver=None)
                self._audit.log(
                    AuditEvent(
                        action="approval_expired",
                        parent_jti=record.parent_jti,
                        scopes=list(record.requested_scopes),
                        decision="deny",
                        reason="approval request timed out without human action",
                        detail={"approval_id": record.approval_id},
                    )
                )
                count += 1
        return count

    # ==================================================================
    # Introspection
    # ==================================================================
    def chain(self, jti: str) -> list[ChainHop]:
        """Reconstruct a capability's lineage from durable records.

        Walks stored metadata rather than reading the token's own chain claim, so
        a caller cannot be the sole source of its own provenance.
        """
        leaf = self.storage.get_token(jti)
        if leaf is None:
            raise KeyError(f"unknown jti {jti}")

        lineage: list[TokenMetadata] = []
        cursor: TokenMetadata | None = leaf
        seen: set[str] = set()
        while cursor is not None and cursor.jti not in seen:
            seen.add(cursor.jti)
            lineage.append(cursor)
            cursor = (
                self.storage.get_token(cursor.parent_jti) if cursor.parent_jti else None
            )
        lineage.reverse()

        revoked = self.storage.revoked_among([m.jti for m in lineage])
        subjects = self.storage.get_subjects([m.subject_id for m in lineage])
        now = utcnow()

        hops: list[ChainHop] = []
        for meta in lineage:
            expires = as_utc(meta.expires_at)
            issued = as_utc(meta.issued_at)
            assert expires is not None and issued is not None
            subject = subjects.get(meta.subject_id)
            hops.append(
                ChainHop(
                    jti=meta.jti,
                    subject_id=meta.subject_id,
                    display_label=subject.display_label if subject else None,
                    scopes=tuple(meta.scopes),
                    depth=meta.depth,
                    issued_at=issued,
                    expires_at=expires,
                    revoked=meta.jti in revoked,
                    expired=expires < now,
                )
            )
        return hops

    def verify_audit_integrity(self) -> IntegrityReport:
        """Walk the audit hash chain and report the first break, if any."""
        return self._audit.verify_integrity()

    def audit_events(
        self,
        *,
        action: str | None = None,
        jti: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Query the audit log."""
        return self.storage.find_audit_rows(action=action, jti=jti, limit=limit)

    def circuit_state(self) -> CircuitState:
        return self._circuit.state()

    def reset_circuit(self) -> None:
        """Break glass: close the breaker. There is no automatic recovery."""
        previous = self._circuit.state()
        self._circuit.reset()
        self._audit.log(
            AuditEvent(
                action="circuit_reset",
                decision="allow",
                reason="break glass: manual circuit reset",
                detail={"was_open": previous.open, "previous_reason": previous.reason},
            )
        )

    def rate_limit_snapshot(self) -> dict[str, int]:
        return self._rate.snapshot()

    def close(self) -> None:
        self.storage.close()

    def __enter__(self) -> "Firewall":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ==================================================================
    # Internals
    # ==================================================================
    def _decode_live(self, token: str) -> TokenClaims:
        """Decode and fully validate a token presented as a delegating parent."""
        try:
            claims = self._tokens.decode(token, verify_exp=False)
        except TokenError as exc:
            raise ParentTokenInvalid(exc.reason) from exc
        if claims.exp < utcnow_ts():
            raise ParentTokenInvalid(REASON_EXPIRED)
        if self.storage.is_revoked(claims.jti):
            raise ParentTokenInvalid(REASON_REVOKED)
        for ancestor in claims.ancestor_jtis:
            if self.storage.is_revoked(ancestor):
                raise ParentTokenInvalid(REASON_REVOKED)
        return claims

    def _assert_root_alive(self, claims: TokenClaims) -> None:
        """A chain is only as good as the root it terminates at."""
        root = self.storage.get_token(claims.root_jti)
        if root is None:
            raise RootChainBroken("chain does not terminate at a known root")
        if root.depth != 0:
            raise RootChainBroken("chain root is not a depth-0 capability")
        expires = as_utc(root.expires_at)
        assert expires is not None
        if expires < utcnow():
            raise RootChainBroken("root capability has expired")
        if self.storage.is_revoked(claims.root_jti):
            raise RootChainBroken("root capability has been revoked")

    def _resolve_subject(self, identifier: str, kind: str):
        subject = self.storage.get_or_create_subject(
            identifier_hash=hash_identifier(identifier, self.config.pii_salt),
            kind=kind,
            display_label=identifier,
        )
        # Lets an exempt raw name match the opaque subject that appears in tokens.
        self.config.register_exempt_subject(identifier, subject.subject_id)
        return subject

    def _persist_token(self, minted: Capability, *, parent_jti: str | None) -> None:
        claims = minted.claims
        self.storage.put_token(
            TokenMetadata(
                jti=claims.jti,
                subject_id=claims.sub,
                parent_jti=parent_jti,
                root_jti=claims.root_jti,
                depth=claims.depth,
                max_depth=claims.max_depth,
                scopes=list(claims.scopes),
                delegation_chain=[e.to_dict() for e in claims.delegation_chain],
                issued_at=from_ts(claims.iat),
                expires_at=from_ts(claims.exp),
                approval_required=claims.approval_required,
                approved_by=claims.approved_by,
            )
        )

    def _claims_from_metadata(self, meta: TokenMetadata) -> TokenClaims:
        """Rebuild claims from durable state, trusting no caller input."""
        from agperms.models import DelegationChainEntry

        issued = as_utc(meta.issued_at)
        expires = as_utc(meta.expires_at)
        assert issued is not None and expires is not None
        return TokenClaims(
            jti=meta.jti,
            sub=meta.subject_id,
            iss=self.config.issuer,
            issued_for=(
                meta.subject_id
                if meta.parent_jti is None
                else f"agent:{meta.parent_jti}"
            ),
            scopes=tuple(meta.scopes),
            delegation_chain=tuple(
                DelegationChainEntry.from_dict(e) for e in meta.delegation_chain
            ),
            depth=meta.depth,
            max_depth=meta.max_depth,
            iat=int(issued.timestamp()),
            exp=int(expires.timestamp()),
            approval_required=meta.approval_required,
            approved_by=meta.approved_by,
            root_jti=meta.root_jti,
        )

    def _park_for_approval(
        self,
        *,
        parent: TokenClaims,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int,
        sensitive: list[str],
    ) -> PendingApproval:
        """Park a sensitive delegation. Nothing is minted here, by design."""
        child_subject = self._resolve_subject(child_agent_id, "agent")
        approval_id = str(uuid.uuid4())
        # The gate must not outlive the parent, or approving a stale request would
        # mint against a dead capability.
        expires_ts = min(
            utcnow_ts() + self.config.approval_timeout_seconds, parent.exp
        )
        record = PendingApproval(
            approval_id=approval_id,
            parent_jti=parent.jti,
            parent_subject_id=parent.sub,
            child_agent_id=child_agent_id,
            child_subject_id=child_subject.subject_id,
            requested_scopes=tuple(requested_scopes),
            sensitive_scopes=tuple(sensitive),
            ttl_seconds=ttl_seconds,
            parent_exp=parent.exp,
            status="pending",
            created_at=utcnow(),
            expires_at=from_ts(expires_ts),
        )
        self.storage.put_approval(record)
        self._audit.log(
            AuditEvent(
                action="approval_pending",
                actor_id=parent.sub,
                parent_jti=parent.jti,
                root_jti=parent.root_jti,
                scopes=requested_scopes,
                decision="pending",
                reason=f"sensitive scopes require approval: {sensitive}",
                depth=parent.depth + 1,
                detail={"approval_id": approval_id, "child_agent_id": child_agent_id},
            )
        )
        return record

    def _load_pending(self, approval_id: str) -> PendingApproval:
        record = self.storage.get_approval(approval_id)
        if record is None:
            raise KeyError(f"unknown approval {approval_id}")
        if record.status == "pending":
            expires = as_utc(record.expires_at)
            assert expires is not None
            if expires < utcnow():
                self._decide_approval(record, status="expired", approver=None)
                raise ValueError(f"approval {approval_id} has expired")
        if record.status != "pending":
            raise ValueError(f"approval {approval_id} is already {record.status}")
        return record

    def _decide_approval(
        self,
        record: PendingApproval,
        *,
        status: str,
        approver: str | None,
        child_jti: str | None = None,
        child_token: str | None = None,
    ) -> None:
        self.storage.update_approval(
            PendingApproval(
                approval_id=record.approval_id,
                parent_jti=record.parent_jti,
                parent_subject_id=record.parent_subject_id,
                child_agent_id=record.child_agent_id,
                child_subject_id=record.child_subject_id,
                requested_scopes=record.requested_scopes,
                sensitive_scopes=record.sensitive_scopes,
                ttl_seconds=record.ttl_seconds,
                parent_exp=record.parent_exp,
                status=status,
                created_at=record.created_at,
                expires_at=record.expires_at,
                decided_at=utcnow(),
                approved_by=approver,
                child_jti=child_jti,
                child_token=child_token,
                collected=record.collected,
            )
        )


def classify_action(action: ActionRecord) -> CompletionState:
    """Classify an action's completion state.

    A pure function, deliberately: this is the rule the whole in-flight feature
    rests on, and it should be testable without a firewall, a store, or a clock.

    An action with no closing record is ``UNKNOWN``, never ``CLEAN``. It might
    have finished, or it might have taken an irreversible step and died -- and
    those are different facts, so the library refuses to guess in the direction
    that happens to be convenient.
    """
    if action.finished_at is None or action.state is None:
        return CompletionState.UNKNOWN
    return action.state


#: How badly each completion state wants a human, independent of reversibility.
#: UNKNOWN outranks PARTIAL because PARTIAL at least tells you the action raised;
#: UNKNOWN tells you nothing at all.
_COMPLETION_URGENCY = {
    CompletionState.UNKNOWN: 2,
    CompletionState.PARTIAL: 1,
    CompletionState.CLEAN: 0,
}


def review_priority(action: ActionRecord) -> int:
    """Sort key for a review queue. Higher means more urgent.

    Combines the two independent facts the library holds about a questionable
    action: how little is known about whether it finished
    (:func:`classify_action`) and how little can be done about it if it did the
    wrong thing (:class:`~agperms.models.Reversibility`). Completion state
    dominates -- the ``* 10`` spacing means no reversibility class can lift a
    PARTIAL above an UNKNOWN -- because "we do not know what happened" is a
    worse position than "we know it failed", whatever the action was.

    Pure, for the same reason :func:`classify_action` is pure: it is a policy
    rule and should be testable without a store.
    """
    return _COMPLETION_URGENCY[classify_action(action)] * 10 + action.reversibility.rank


__all__ = ["ActionHandle", "Firewall", "classify_action", "review_priority"]
