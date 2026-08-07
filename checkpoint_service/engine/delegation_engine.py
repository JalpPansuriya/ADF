"""Delegation Engine -- the actual enforcement checkpoint.

Implements PRD Section 7 with one deliberate ordering change in :meth:`verify`:
the JWT signature is verified **before** any claim (including ``jti``) is read.
The PRD's pseudocode calls ``is_revoked(token.jti)`` first, which trusts an
attacker-controlled value. See DECISIONS.md 2026-08-07 (verify order).

Enforcement rules, all applied at mint time (PRD Section 5):

1. ``child.scopes ⊆ parent.scopes`` -- equal allowed, exceeding never.
2. ``child.exp ≤ parent.exp``.
3. ``child.depth = parent.depth + 1``, rejected above ``max_depth``.
4. ``child.delegation_chain = parent.chain + [parent's own entry]``.
5. The chain must terminate at a live (non-expired, non-revoked) root token.
6. Sensitive scopes divert to the human-approval gate; no token is minted.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from checkpoint_service.config import Settings
from checkpoint_service.engine.audit_logger import AuditEvent, AuditLogger
from checkpoint_service.engine.guardrails import (
    AnomalyDetector,
    CircuitBreaker,
    CircuitOpen,
    RateLimiter,
)
from checkpoint_service.engine.revocation import RevocationStore
from checkpoint_service.engine.subjects import SubjectRegistry
from checkpoint_service.engine.token_engine import (
    REASON_CIRCUIT_OPEN,
    REASON_EXPIRED,
    REASON_REVOKED,
    REASON_SCOPE_NOT_GRANTED,
    MintedToken,
    TokenEngine,
    TokenError,
)
from checkpoint_service.models.audit import PendingApproval, TokenRecord
from checkpoint_service.models.token import TokenClaims
from checkpoint_service.utils import as_utc, from_ts, utcnow, utcnow_ts


class DelegationDenied(Exception):
    """Base class for a refused delegation."""


class ScopeEscalationDenied(DelegationDenied):
    """Requested scopes exceed what the parent holds."""

    def __init__(self, requested: list[str], allowed_max: list[str], denied: list[str]) -> None:
        super().__init__(f"scope escalation denied: {denied}")
        self.requested = requested
        self.allowed_max = allowed_max
        self.denied = denied


class DepthLimitExceeded(DelegationDenied):
    def __init__(self, depth: int, max_depth: int) -> None:
        super().__init__(f"max delegation depth reached ({depth} > {max_depth})")
        self.depth = depth
        self.max_depth = max_depth


class ParentTokenInvalid(DelegationDenied):
    """The presented parent token is unusable (expired/revoked/forged)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RootChainBroken(DelegationDenied):
    """The chain does not terminate at a live root token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class VerifyOutcome:
    valid: bool
    reason: str | None = None
    claims: TokenClaims | None = None
    latency_ms: float = 0.0


@dataclass
class PendingApprovalCreated:
    """Returned instead of a token when a sensitive scope is requested."""

    approval_id: str
    requested_scopes: list[str]
    sensitive_scopes: list[str]
    expires_at: str


class DelegationEngine:
    def __init__(
        self,
        *,
        settings: Settings,
        token_engine: TokenEngine,
        revocation: RevocationStore,
        audit: AuditLogger,
        subjects: SubjectRegistry,
        rate_limiter: RateLimiter,
        circuit: CircuitBreaker,
        anomaly: AnomalyDetector,
    ) -> None:
        self._settings = settings
        self._tokens = token_engine
        self._revocation = revocation
        self._audit = audit
        self._subjects = subjects
        self._rate = rate_limiter
        self._circuit = circuit
        self._anomaly = anomaly

    # ------------------------------------------------------------------
    # Root minting
    # ------------------------------------------------------------------
    def mint_root(
        self,
        session: Session,
        *,
        human_id: str,
        scopes: list[str],
        ttl_seconds: int,
        max_depth: int | None,
    ) -> MintedToken:
        """Mint a depth-0 token for a human issuer (PRD 6.1)."""
        subject = self._subjects.resolve_or_create(session, human_id, "human")
        effective_depth = max_depth or self._settings.max_delegation_depth
        ttl = min(ttl_seconds, self._settings.max_ttl_seconds)

        minted = self._tokens.mint_root(
            subject_id=subject.subject_id,
            scopes=scopes,
            ttl_seconds=ttl,
            max_depth=effective_depth,
        )
        self._persist_token(session, minted, parent_jti=None)
        self._audit.log(
            AuditEvent(
                action="root_token_minted",
                actor_id=subject.subject_id,
                actor_hash=subject.identifier_hash,
                jti=minted.jti,
                root_jti=minted.jti,
                scopes=minted.claims.scopes,
                depth=0,
                decision="allow",
                detail={"ttl_seconds": ttl, "max_depth": effective_depth},
            )
        )
        return minted

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------
    def delegate(
        self,
        session: Session,
        *,
        parent_token: str,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int,
    ) -> MintedToken | PendingApprovalCreated:
        """Mint a narrowed child token, or divert to the approval gate.

        Order matters. The parent token is fully validated first so that a forged
        or dead token can never consume rate budget attributed to a real agent,
        nor reach the scope comparison.
        """
        self._circuit.check()

        parent = self._decode_live_parent(session, parent_token)

        # Rate limit keyed on the verified subject, not a client-supplied id.
        self._rate.check(parent.sub, "delegate")

        self._assert_root_alive(session, parent)

        denied = [s for s in requested_scopes if s not in parent.scope_set]
        if denied:
            self._audit.log(
                AuditEvent(
                    action="scope_escalation_denied",
                    actor_id=parent.sub,
                    jti=None,
                    parent_jti=parent.jti,
                    root_jti=parent.root_jti,
                    scopes=requested_scopes,
                    denied_scopes=denied,
                    decision="deny",
                    reason="requested scopes exceed parent grant",
                    depth=parent.depth + 1,
                    detail={"child_agent_id": child_agent_id},
                )
            )
            self._circuit.record(error=True, subject_id=parent.sub, policy_denial=True)
            raise ScopeEscalationDenied(
                requested=requested_scopes,
                allowed_max=sorted(parent.scope_set),
                denied=denied,
            )

        child_depth = parent.depth + 1
        if child_depth > parent.max_depth:
            self._audit.log(
                AuditEvent(
                    action="depth_limit_exceeded",
                    actor_id=parent.sub,
                    parent_jti=parent.jti,
                    root_jti=parent.root_jti,
                    scopes=requested_scopes,
                    decision="deny",
                    reason=f"depth {child_depth} exceeds max_depth {parent.max_depth}",
                    depth=child_depth,
                    detail={"child_agent_id": child_agent_id},
                )
            )
            self._circuit.record(error=True, subject_id=parent.sub, policy_denial=True)
            raise DepthLimitExceeded(child_depth, parent.max_depth)

        anomaly = self._anomaly.observe_delegation(parent.sub, len(requested_scopes))
        if anomaly:
            self._audit.log(
                AuditEvent(
                    action="anomaly_detected",
                    actor_id=parent.sub,
                    parent_jti=parent.jti,
                    root_jti=parent.root_jti,
                    scopes=requested_scopes,
                    decision="flag",
                    reason=anomaly,
                    detail={"child_agent_id": child_agent_id, "auto_blocked": False},
                )
            )

        # exp is clamped here and nowhere else, so a child can never outlive its
        # parent regardless of the ttl requested.
        child_exp = min(utcnow_ts() + ttl_seconds, parent.exp)

        sensitive = [s for s in requested_scopes if s in self._settings.sensitive_scopes]
        if sensitive:
            pending = self._create_pending_approval(
                session,
                parent=parent,
                child_agent_id=child_agent_id,
                requested_scopes=requested_scopes,
                ttl_seconds=ttl_seconds,
            )
            self._circuit.record(error=False, subject_id=parent.sub)
            return pending

        child_subject = self._subjects.resolve_or_create(session, child_agent_id, "agent")
        minted = self._tokens.mint_child(
            parent=parent,
            child_subject_id=child_subject.subject_id,
            scopes=requested_scopes,
            exp=child_exp,
        )
        self._persist_token(session, minted, parent_jti=parent.jti)
        self._revocation.record_edge(session, parent.jti, minted.jti)
        self._audit.log(
            AuditEvent(
                action="token_minted",
                actor_id=parent.sub,
                jti=minted.jti,
                parent_jti=parent.jti,
                root_jti=minted.claims.root_jti,
                scopes=minted.claims.scopes,
                decision="allow",
                depth=minted.claims.depth,
                detail={
                    "child_agent_id": child_agent_id,
                    "child_subject_id": child_subject.subject_id,
                    "exp": minted.claims.exp,
                },
            )
        )
        self._circuit.record(error=False, subject_id=parent.sub)
        return minted

    # ------------------------------------------------------------------
    # Verification (the hot path)
    # ------------------------------------------------------------------
    def verify(
        self, session: Session, *, token: str, required_scope: str
    ) -> VerifyOutcome:
        """Enforcement checkpoint called before any agent action.

        Check order: circuit breaker (reads nothing) -> signature -> expiry ->
        revocation -> scope. No claim is read before the signature is verified.
        """
        started = time.perf_counter()

        if self._circuit.is_open():
            return VerifyOutcome(
                valid=False,
                reason=REASON_CIRCUIT_OPEN,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )

        # 1. Signature + issuer + required claims. Expiry is checked separately
        #    below so the two failures can be reported distinctly.
        try:
            claims = self._tokens.decode(token, verify_exp=False)
        except TokenError as exc:
            # A malformed/forged token is a *client* error, not a system fault.
            # Counting it as a breaker fault would let anyone open the circuit for
            # every other agent just by posting garbage.
            self._circuit.record(error=True, policy_denial=True)
            self._audit.log(
                AuditEvent(
                    action="verify_denied",
                    required_scope=required_scope,
                    decision="deny",
                    reason=exc.reason,
                )
            )
            return VerifyOutcome(
                valid=False,
                reason=exc.reason,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )

        # From here on, claims are authenticated and safe to read.
        def deny(reason: str) -> VerifyOutcome:
            # A verify denial is the firewall working as intended, not a fault.
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
                    scopes=claims.scopes,
                    decision="deny",
                    reason=reason,
                    depth=claims.depth,
                )
            )
            return VerifyOutcome(
                valid=False,
                reason=reason,
                claims=claims,
                latency_ms=(time.perf_counter() - started) * 1000.0,
            )

        # 2. Rate limit, keyed on the authenticated subject. Done before the
        #    remaining checks so a flood cannot drive database lookups, and after
        #    the signature check so the budget cannot be charged to a forged id.
        #    Raises RateLimitExceeded, surfaced by the route as 429.
        self._rate.check(claims.sub, "verify")

        # 3. Expiry.
        if claims.exp < utcnow_ts():
            return deny(REASON_EXPIRED)

        # 4. Revocation (own jti, then every ancestor -- revoking a parent must
        #    kill descendants even if a subtree edge was never recorded).
        if self._revocation.is_revoked(claims.jti, session):
            return deny(REASON_REVOKED)
        for entry in claims.delegation_chain:
            if self._revocation.is_revoked(entry.jti, session):
                return deny(REASON_REVOKED)

        # 5. Scope.
        if required_scope not in claims.scope_set:
            return deny(REASON_SCOPE_NOT_GRANTED)

        self._circuit.record(error=False, subject_id=claims.sub)
        latency_ms = (time.perf_counter() - started) * 1000.0
        self._audit.log(
            AuditEvent(
                action="verify_success",
                actor_id=claims.sub,
                jti=claims.jti,
                root_jti=claims.root_jti,
                required_scope=required_scope,
                scopes=claims.scopes,
                decision="allow",
                depth=claims.depth,
                latency_ms=latency_ms,
            )
        )
        return VerifyOutcome(valid=True, claims=claims, latency_ms=latency_ms)

    # ------------------------------------------------------------------
    # Approval gate
    # ------------------------------------------------------------------
    def _create_pending_approval(
        self,
        session: Session,
        *,
        parent: TokenClaims,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int,
    ) -> PendingApprovalCreated:
        """Park a sensitive delegation. No token is minted here by design."""
        sensitive = sorted(
            s for s in requested_scopes if s in self._settings.sensitive_scopes
        )
        child_subject = self._subjects.resolve_or_create(session, child_agent_id, "agent")
        approval_id = str(uuid.uuid4())
        # The gate itself must not outlive the parent token, otherwise approving
        # a stale request would mint against a dead parent.
        expires_at = min(
            utcnow_ts() + self._settings.approval_timeout_seconds, parent.exp
        )
        record = PendingApproval(
            approval_id=approval_id,
            parent_jti=parent.jti,
            parent_subject_id=parent.sub,
            child_agent_id=child_agent_id,
            child_subject_id=child_subject.subject_id,
            requested_scopes=requested_scopes,
            sensitive_scopes=sensitive,
            ttl_seconds=ttl_seconds,
            parent_exp=parent.exp,
            status="pending",
            expires_at=from_ts(expires_at),
        )
        session.add(record)
        session.flush()

        self._audit.log(
            AuditEvent(
                action="approval_pending",
                actor_id=parent.sub,
                parent_jti=parent.jti,
                root_jti=parent.root_jti,
                scopes=requested_scopes,
                decision="pending",
                reason=f"sensitive scopes require human approval: {sensitive}",
                depth=parent.depth + 1,
                detail={"approval_id": approval_id, "child_agent_id": child_agent_id},
            )
        )
        return PendingApprovalCreated(
            approval_id=approval_id,
            requested_scopes=requested_scopes,
            sensitive_scopes=sensitive,
            expires_at=from_ts(expires_at).isoformat(),
        )

    def approve(
        self, session: Session, *, approval_id: str, approver_id: str
    ) -> tuple[PendingApproval, MintedToken]:
        """Human approves a pending delegation; the child token is minted here.

        The parent token is re-validated at approval time -- it may have been
        revoked or expired while the request sat in the queue.
        """
        record = self._load_pending(session, approval_id)

        parent_record = session.get(TokenRecord, record.parent_jti)
        if parent_record is None:  # pragma: no cover - defensive
            raise RootChainBroken("parent token record not found")
        if self._revocation.is_revoked(record.parent_jti, session):
            record.status = "denied"
            record.decided_at = utcnow()
            record.approved_by = approver_id
            session.flush()
            self._audit.log(
                AuditEvent(
                    action="approval_rejected",
                    actor_id=approver_id,
                    parent_jti=record.parent_jti,
                    decision="deny",
                    reason="parent token was revoked while approval was pending",
                    detail={"approval_id": approval_id},
                )
            )
            raise ParentTokenInvalid(REASON_REVOKED)
        if record.parent_exp < utcnow_ts():
            record.status = "expired"
            record.decided_at = utcnow()
            session.flush()
            raise ParentTokenInvalid(REASON_EXPIRED)

        # Reconstruct the parent's claims from the persisted record so approval
        # does not require the agent to re-present its token.
        parent_claims = self._claims_from_record(parent_record)
        child_exp = min(utcnow_ts() + record.ttl_seconds, record.parent_exp)

        minted = self._tokens.mint_child(
            parent=parent_claims,
            child_subject_id=record.child_subject_id,
            scopes=list(record.requested_scopes),
            exp=child_exp,
            approval_required=True,
            approved_by=approver_id,
        )
        self._persist_token(session, minted, parent_jti=record.parent_jti)
        self._revocation.record_edge(session, record.parent_jti, minted.jti)

        record.status = "approved"
        record.decided_at = utcnow()
        record.approved_by = approver_id
        record.child_jti = minted.jti
        record.child_token = minted.token
        session.flush()

        self._audit.log(
            AuditEvent(
                action="approval_granted",
                actor_id=approver_id,
                jti=minted.jti,
                parent_jti=record.parent_jti,
                root_jti=minted.claims.root_jti,
                scopes=minted.claims.scopes,
                decision="allow",
                depth=minted.claims.depth,
                detail={
                    "approval_id": approval_id,
                    "child_agent_id": record.child_agent_id,
                    "sensitive_scopes": list(record.sensitive_scopes),
                },
            )
        )
        return record, minted

    def deny(
        self, session: Session, *, approval_id: str, approver_id: str
    ) -> PendingApproval:
        """Human denies a pending delegation. Nothing is ever minted."""
        record = self._load_pending(session, approval_id)
        record.status = "denied"
        record.decided_at = utcnow()
        record.approved_by = approver_id
        session.flush()
        self._audit.log(
            AuditEvent(
                action="approval_denied",
                actor_id=approver_id,
                parent_jti=record.parent_jti,
                scopes=list(record.requested_scopes),
                decision="deny",
                reason="human denied the delegation request",
                detail={
                    "approval_id": approval_id,
                    "child_agent_id": record.child_agent_id,
                },
            )
        )
        return record

    def expire_stale_approvals(self, session: Session) -> int:
        """Mark timed-out approval requests expired (PRD 8.2)."""
        now = utcnow()
        stale = session.scalars(
            select(PendingApproval).where(PendingApproval.status == "pending")
        ).all()
        count = 0
        for record in stale:
            if as_utc(record.expires_at) < now:
                record.status = "expired"
                record.decided_at = now
                count += 1
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
        if count:
            session.flush()
        return count

    def _load_pending(self, session: Session, approval_id: str) -> PendingApproval:
        record = session.get(PendingApproval, approval_id)
        if record is None:
            raise KeyError(f"unknown approval_id: {approval_id}")
        if record.status == "pending" and as_utc(record.expires_at) < utcnow():
            record.status = "expired"
            record.decided_at = utcnow()
            session.flush()
        if record.status != "pending":
            raise ValueError(f"approval {approval_id} is already {record.status}")
        return record

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def revoke(
        self, session: Session, *, jti: str, reason: str | None, actor_id: str
    ) -> tuple[list[str], float]:
        revoked, latency_ms = self._revocation.revoke_subtree(session, jti, reason=reason)
        self._audit.log(
            AuditEvent(
                action="token_revoked",
                actor_id=actor_id,
                jti=jti,
                decision="revoke",
                reason=reason,
                latency_ms=latency_ms,
                detail={"subtree_count": len(revoked), "revoked_jtis": revoked},
            )
        )
        return revoked, latency_ms

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _decode_live_parent(self, session: Session, parent_token: str) -> TokenClaims:
        """Decode and fully validate the presented parent token."""
        try:
            claims = self._tokens.decode(parent_token, verify_exp=False)
        except TokenError as exc:
            raise ParentTokenInvalid(exc.reason) from exc

        if claims.exp < utcnow_ts():
            raise ParentTokenInvalid(REASON_EXPIRED)
        if self._revocation.is_revoked(claims.jti, session):
            raise ParentTokenInvalid(REASON_REVOKED)
        for entry in claims.delegation_chain:
            if self._revocation.is_revoked(entry.jti, session):
                raise ParentTokenInvalid(REASON_REVOKED)
        return claims

    def _assert_root_alive(self, session: Session, parent: TokenClaims) -> None:
        """PRD 5 rule 5: the chain must terminate at a live root token."""
        root_record = session.get(TokenRecord, parent.root_jti)
        if root_record is None:
            raise RootChainBroken("chain does not terminate at a known root token")
        if root_record.depth != 0:
            raise RootChainBroken("chain root is not a depth-0 token")
        if as_utc(root_record.expires_at) < utcnow():
            raise RootChainBroken("root token has expired")
        if self._revocation.is_revoked(parent.root_jti, session):
            raise RootChainBroken("root token has been revoked")

    def _persist_token(
        self, session: Session, minted: MintedToken, *, parent_jti: str | None
    ) -> None:
        claims = minted.claims
        session.add(
            TokenRecord(
                jti=claims.jti,
                subject_id=claims.sub,
                parent_jti=parent_jti,
                root_jti=claims.root_jti,
                depth=claims.depth,
                max_depth=claims.max_depth,
                scopes=claims.scopes,
                delegation_chain=[e.model_dump() for e in claims.delegation_chain],
                issued_at=from_ts(claims.iat),
                expires_at=from_ts(claims.exp),
                approval_required=claims.approval_required,
                approved_by=claims.approved_by,
            )
        )
        session.flush()

    def _claims_from_record(self, record: TokenRecord) -> TokenClaims:
        """Rebuild claims from the server-side record (no client input trusted)."""
        from checkpoint_service.models.token import DelegationChainEntry

        return TokenClaims(
            jti=record.jti,
            sub=record.subject_id,
            iss=self._settings.issuer,
            issued_for=(
                record.subject_id
                if record.parent_jti is None
                else f"agent:{record.parent_jti}"
            ),
            scopes=list(record.scopes),
            delegation_chain=[
                DelegationChainEntry.model_validate(e) for e in record.delegation_chain
            ],
            depth=record.depth,
            max_depth=record.max_depth,
            iat=int(as_utc(record.issued_at).timestamp()),
            exp=int(as_utc(record.expires_at).timestamp()),
            approval_required=record.approval_required,
            approved_by=record.approved_by,
            root_jti=record.root_jti,
        )

