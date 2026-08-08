"""Data types that cross the public API boundary.

Plain dataclasses rather than pydantic models: pydantic is a heavy dependency to
force on every consumer of a small library, and the validation that actually
matters here (rejecting a token whose claim set does not match the schema) is
done explicitly in :meth:`TokenClaims.from_payload` so an unexpected or injected
claim is a hard error rather than a silently-ignored extra.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agperms._time import as_utc, from_ts
from agperms.errors import TokenError


class CompletionState(str, Enum):
    """How an in-flight action stood at the moment its token was revoked.

    ``UNKNOWN`` is never treated as ``CLEAN``. An action whose closing record is
    absent might have completed, or might have taken an irreversible step and
    died -- and those are not the same thing, so the library refuses to guess.
    """

    CLEAN = "CLEAN"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"

    def needs_human_review(self) -> bool:
        return self is not CompletionState.CLEAN


class Reversibility(str, Enum):
    """How recoverable an action's effect is, if it turns out to be wrong.

    The taxonomy is from *Revisable by Design: A Theory of Streaming LLM Agent
    Execution* (arXiv:2604.23283), whose central result is that an agent's
    flexibility is bounded by its reversibility -- conflicting irreversible
    actions make full specification satisfaction impossible, and that is a
    property of the action space rather than of any algorithm. If that is true,
    reversibility belongs in the policy that hands out capabilities, not only in
    a post-hoc report.

    This is orthogonal to :class:`CompletionState`. Completion state answers
    *did it finish*; reversibility answers *how bad is it if it did the wrong
    thing*. An UNKNOWN idempotent read and an UNKNOWN funds transfer are the
    same completion state and nowhere near the same problem.
    """

    #: Repeating it changes nothing. A read, a status check.
    IDEMPOTENT = "IDEMPOTENT"
    #: A true undo exists and restores the prior state.
    REVERSIBLE = "REVERSIBLE"
    #: No undo, but a corrective action exists -- a refund after a charge.
    COMPENSABLE = "COMPENSABLE"
    #: No undo and no compensation. A sent email cannot be unsent.
    IRREVERSIBLE = "IRREVERSIBLE"

    @property
    def rank(self) -> int:
        """Severity order: 0 is fully recoverable, 3 is unrecoverable.

        Comparison operators are deliberately *not* overridden. This is a
        ``str`` enum, so ``str.__lt__``/``__gt__`` already exist and would order
        members alphabetically (COMPENSABLE < IDEMPOTENT < IRREVERSIBLE <
        REVERSIBLE) -- which is not the severity order and is not worth the
        confusion of a partial override. Sort and compare on ``.rank``
        explicitly: ``max(members, key=lambda r: r.rank)``.
        """
        return _REVERSIBILITY_RANK[self.value]


def worst_of(classes: "Iterable[Reversibility]") -> "Reversibility | None":
    """The least recoverable member of ``classes``, or ``None`` if empty."""
    ranked = sorted(classes, key=lambda r: r.rank)
    return ranked[-1] if ranked else None


_REVERSIBILITY_RANK = {
    "IDEMPOTENT": 0,
    "REVERSIBLE": 1,
    "COMPENSABLE": 2,
    "IRREVERSIBLE": 3,
}


@dataclass(frozen=True, slots=True)
class DelegationChainEntry:
    """One hop of custody: who granted, holding what, when."""

    agent_id: str
    jti: str
    scopes: tuple[str, ...]
    ts: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "jti": self.jti,
            "scopes": list(self.scopes),
            "ts": self.ts,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "DelegationChainEntry":
        if not isinstance(raw, dict):
            raise TokenError("malformed_token", "delegation_chain entry is not an object")
        try:
            scopes = raw["scopes"]
            if not isinstance(scopes, (list, tuple)):
                raise TypeError("scopes must be a list")
            return cls(
                agent_id=str(raw["agent_id"]),
                jti=str(raw["jti"]),
                scopes=tuple(str(s) for s in scopes),
                ts=str(raw["ts"]),
            )
        except (KeyError, TypeError) as exc:
            raise TokenError(
                "malformed_token", f"bad delegation_chain entry: {exc}"
            ) from exc


#: Every claim agperms writes. A decoded token carrying anything else is
#: rejected: an unknown claim is either a version mismatch or an injection
#: attempt, and neither should be quietly accepted.
_ALLOWED_CLAIMS = frozenset(
    {
        "jti",
        "sub",
        "iss",
        "issued_for",
        "scopes",
        "delegation_chain",
        "depth",
        "max_depth",
        "iat",
        "exp",
        "approval_required",
        "approved_by",
        "root_jti",
    }
)


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """The decoded, signature-verified payload of a capability token."""

    jti: str
    sub: str
    iss: str
    issued_for: str
    scopes: tuple[str, ...]
    depth: int
    max_depth: int
    iat: int
    exp: int
    root_jti: str
    delegation_chain: tuple[DelegationChainEntry, ...] = ()
    approval_required: bool = False
    approved_by: str | None = None

    # ------------------------------------------------------------------
    @property
    def scope_set(self) -> frozenset[str]:
        return frozenset(self.scopes)

    @property
    def expires_at(self) -> _dt.datetime:
        return from_ts(self.exp)

    @property
    def issued_at(self) -> _dt.datetime:
        return from_ts(self.iat)

    @property
    def is_root(self) -> bool:
        return self.depth == 0

    @property
    def ancestor_jtis(self) -> tuple[str, ...]:
        return tuple(entry.jti for entry in self.delegation_chain)

    def to_payload(self) -> dict[str, Any]:
        """The exact dict that gets signed."""
        return {
            "jti": self.jti,
            "sub": self.sub,
            "iss": self.iss,
            "issued_for": self.issued_for,
            "scopes": list(self.scopes),
            "delegation_chain": [e.to_dict() for e in self.delegation_chain],
            "depth": self.depth,
            "max_depth": self.max_depth,
            "iat": self.iat,
            "exp": self.exp,
            "approval_required": self.approval_required,
            "approved_by": self.approved_by,
            "root_jti": self.root_jti,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TokenClaims":
        """Validate a decoded JWT payload against the closed claim schema."""
        if not isinstance(payload, dict):
            raise TokenError("malformed_token", "payload is not an object")

        extra = set(payload) - _ALLOWED_CLAIMS
        if extra:
            raise TokenError(
                "malformed_token", f"unexpected claim(s): {sorted(extra)}"
            )

        try:
            scopes = payload["scopes"]
            if not isinstance(scopes, (list, tuple)):
                raise TypeError("scopes must be a list")
            chain_raw = payload.get("delegation_chain") or []
            if not isinstance(chain_raw, (list, tuple)):
                raise TypeError("delegation_chain must be a list")

            approved_by = payload.get("approved_by")
            return cls(
                jti=str(payload["jti"]),
                sub=str(payload["sub"]),
                iss=str(payload["iss"]),
                issued_for=str(payload["issued_for"]),
                scopes=tuple(str(s) for s in scopes),
                delegation_chain=tuple(
                    DelegationChainEntry.from_dict(e) for e in chain_raw
                ),
                depth=int(payload["depth"]),
                max_depth=int(payload["max_depth"]),
                iat=int(payload["iat"]),
                exp=int(payload["exp"]),
                approval_required=bool(payload.get("approval_required", False)),
                approved_by=None if approved_by is None else str(approved_by),
                root_jti=str(payload["root_jti"]),
            )
        except TokenError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenError("malformed_token", f"bad claim set: {exc}") from exc


@dataclass(frozen=True, slots=True)
class Capability:
    """A minted token plus the metadata a caller needs, without re-decoding it."""

    token: str
    claims: TokenClaims

    @property
    def jti(self) -> str:
        return self.claims.jti

    @property
    def subject(self) -> str:
        return self.claims.sub

    @property
    def scopes(self) -> tuple[str, ...]:
        return self.claims.scopes

    @property
    def depth(self) -> int:
        return self.claims.depth

    @property
    def expires_at(self) -> _dt.datetime:
        return self.claims.expires_at

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return (
            f"Capability(jti={self.jti[:8]}…, subject={self.subject}, "
            f"scopes={list(self.scopes)}, depth={self.depth})"
        )


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of a capability check."""

    valid: bool
    reason: str | None = None
    claims: TokenClaims | None = None
    latency_ms: float = 0.0

    def __bool__(self) -> bool:
        return self.valid

    @property
    def subject(self) -> str | None:
        return self.claims.sub if self.claims else None

    @property
    def remaining_scopes(self) -> tuple[str, ...]:
        return self.claims.scopes if self.claims else ()

    def raise_for_status(self) -> None:
        """Raise :class:`~agperms.errors.Denied` unless the check passed."""
        if not self.valid:
            from agperms.errors import Denied

            raise Denied(self.reason or "denied")


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """A delegation parked at the human-approval gate. No token exists yet."""

    approval_id: str
    parent_jti: str
    parent_subject_id: str
    child_agent_id: str
    child_subject_id: str
    requested_scopes: tuple[str, ...]
    sensitive_scopes: tuple[str, ...]
    ttl_seconds: int
    #: The parent's expiry, snapshotted at request time. Reused verbatim when
    #: minting so a slow approval cannot extend the child beyond what was true
    #: when the request was made.
    parent_exp: int
    status: str
    created_at: _dt.datetime
    expires_at: _dt.datetime
    decided_at: _dt.datetime | None = None
    approved_by: str | None = None
    child_jti: str | None = None
    child_token: str | None = None
    collected: bool = False

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"


@dataclass(frozen=True, slots=True)
class RevocationResult:
    """What a revoke actually did, including in-flight findings."""

    revoked_jtis: tuple[str, ...]
    latency_ms: float
    #: Actions that were open when the revoke landed and now need a human.
    reviews: tuple["ActionReview", ...] = ()

    @property
    def subtree_count(self) -> int:
        return len(self.revoked_jtis)

    @property
    def needs_review(self) -> bool:
        return bool(self.reviews)


@dataclass(frozen=True, slots=True)
class ActionRecord:
    """An action a caller declared via ``Firewall.action``."""

    action_id: str
    jti: str
    subject_id: str
    name: str
    scope: str
    started_at: _dt.datetime
    finished_at: _dt.datetime | None = None
    state: CompletionState | None = None
    failure_reason: str | None = None
    #: How recoverable this action's effect is. Defaults to the worst case: an
    #: unclassified scope is assumed unrecoverable, for the same reason an action
    #: with no closing record is UNKNOWN rather than CLEAN -- the library does not
    #: guess in the direction that happens to be convenient.
    reversibility: Reversibility = Reversibility.IRREVERSIBLE

    @property
    def is_open(self) -> bool:
        return self.finished_at is None


@dataclass(frozen=True, slots=True)
class ActionReview:
    """A PARTIAL/UNKNOWN finding awaiting human closure.

    This is a queryable cache of a *conclusion*. The evidentiary record -- the
    original action events and any human note -- lives in the hash-chained audit
    log, so the two can be cross-checked rather than trusted blindly.
    """

    review_id: str
    jti: str
    action_id: str
    action_name: str
    classification: CompletionState
    revoked_at: _dt.datetime
    revocation_root_jti: str
    reviewed: bool = False
    reviewed_by: str | None = None
    reviewed_at: _dt.datetime | None = None

    def __post_init__(self) -> None:
        if self.classification is CompletionState.CLEAN:
            raise ValueError(
                "CLEAN actions do not need review; only PARTIAL/UNKNOWN are queued"
            )


@dataclass(frozen=True, slots=True)
class ChainHop:
    """One hop of a reconstructed lineage, rebuilt from durable records."""

    jti: str
    subject_id: str
    display_label: str | None
    scopes: tuple[str, ...]
    depth: int
    issued_at: _dt.datetime
    expires_at: _dt.datetime
    revoked: bool
    expired: bool


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """Result of walking the audit hash chain."""

    intact: bool
    rows_checked: int
    first_broken_row_id: int | None
    detail: str

    def __bool__(self) -> bool:
        return self.intact


@dataclass
class TokenMetadata:
    """Durable metadata for a minted token, used to rebuild lineage."""

    jti: str
    subject_id: str
    parent_jti: str | None
    root_jti: str
    depth: int
    max_depth: int
    scopes: list[str]
    delegation_chain: list[dict[str, Any]]
    issued_at: _dt.datetime
    expires_at: _dt.datetime
    approval_required: bool = False
    approved_by: str | None = None

    @property
    def is_expired(self) -> bool:
        expires = as_utc(self.expires_at)
        assert expires is not None
        from agperms._time import utcnow

        return expires < utcnow()


@dataclass
class Subject:
    """Opaque subject id bound to a salted hash of the real identifier."""

    subject_id: str
    identifier_hash: str
    kind: str
    display_label: str
    created_at: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))


__all__ = [
    "ActionRecord",
    "ActionReview",
    "Capability",
    "ChainHop",
    "CompletionState",
    "DelegationChainEntry",
    "IntegrityReport",
    "PendingApproval",
    "RevocationResult",
    "Reversibility",
    "Subject",
    "TokenClaims",
    "TokenMetadata",
    "VerifyResult",
    "worst_of",
]
