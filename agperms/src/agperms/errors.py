"""Exceptions raised by agperms.

Every denial is a subclass of :class:`PermissionError` so that a caller which
only handles the builtin still fails safe rather than proceeding without a
capability.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Denial reasons. Deliberately coarse: a caller learns *that* a token is
# unusable, not the internal detail of which cryptographic check failed.
# ---------------------------------------------------------------------------
REASON_EXPIRED = "expired"
REASON_REVOKED = "revoked"
REASON_INVALID_SIGNATURE = "invalid_signature"
REASON_SCOPE_NOT_GRANTED = "scope_not_granted"
REASON_CIRCUIT_OPEN = "circuit_open"
REASON_MALFORMED = "malformed_token"
REASON_MISSING_TOKEN = "missing_token"


class AgpermsError(Exception):
    """Base class for every agperms error."""


class ConfigurationError(AgpermsError):
    """Configuration is missing or unsafe. Raised at construction, never later."""


class StorageError(AgpermsError):
    """The storage backend failed in a way that cannot be safely ignored."""


class TokenError(AgpermsError):
    """A token could not be decoded or failed a cryptographic check."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


class Denied(PermissionError, AgpermsError):
    """A capability operation was refused.

    Subclasses ``PermissionError`` so ``except PermissionError`` catches every
    denial, which is the failure mode a caller most likely wrote code for.
    """

    def __init__(self, reason: str, **context: object) -> None:
        super().__init__(reason)
        self.reason = reason
        self.context = context


class ScopeEscalationDenied(Denied):
    """A delegation requested scopes the parent does not hold.

    The single invariant this library exists to enforce.
    """

    def __init__(
        self,
        requested: list[str],
        allowed_max: list[str],
        denied_scopes: list[str],
    ) -> None:
        super().__init__(
            "scope_escalation_denied",
            requested=requested,
            allowed_max=allowed_max,
            denied_scopes=denied_scopes,
        )
        self.requested = requested
        self.allowed_max = allowed_max
        self.denied_scopes = denied_scopes

    def __str__(self) -> str:
        return (
            f"scope escalation denied: {self.denied_scopes} not held by the "
            f"delegating token (it holds {self.allowed_max})"
        )


class DepthLimitExceeded(Denied):
    """The delegation chain is already at its maximum depth."""

    def __init__(self, depth: int, max_depth: int) -> None:
        super().__init__("depth_limit_exceeded", depth=depth, max_depth=max_depth)
        self.depth = depth
        self.max_depth = max_depth

    def __str__(self) -> str:
        return f"delegation depth {self.depth} exceeds max_depth {self.max_depth}"


class ParentTokenInvalid(Denied):
    """The token presented as the delegating parent is unusable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)

    def __str__(self) -> str:
        return f"parent token invalid: {self.reason}"


class RootChainBroken(Denied):
    """The chain does not terminate at a live, human-issued root token."""

    def __init__(self, detail: str) -> None:
        super().__init__("root_chain_broken", detail=detail)
        self.detail = detail

    def __str__(self) -> str:
        return f"root chain broken: {self.detail}"


class ApprovalRequired(Denied):
    """A sensitive scope was requested; no token exists until a human approves.

    This is not a failure. It is the approval gate working: the delegation is
    parked, nothing was minted, and ``approval_id`` identifies the pending
    request. Subclasses :class:`Denied` so a caller that ignores it fails safe
    rather than proceeding tokenless.
    """

    def __init__(
        self,
        approval_id: str,
        requested_scopes: list[str],
        sensitive_scopes: list[str],
    ) -> None:
        super().__init__(
            "approval_required",
            approval_id=approval_id,
            requested_scopes=requested_scopes,
            sensitive_scopes=sensitive_scopes,
        )
        self.approval_id = approval_id
        self.requested_scopes = requested_scopes
        self.sensitive_scopes = sensitive_scopes

    def __str__(self) -> str:
        return (
            f"human approval required for {self.sensitive_scopes} "
            f"(approval_id={self.approval_id}); no token was minted"
        )


class RateLimitExceeded(Denied):
    """An agent exceeded its sliding-window call budget."""

    def __init__(self, subject_id: str, limit: int, window_seconds: int) -> None:
        super().__init__(
            "rate_limit_exceeded",
            subject_id=subject_id,
            limit=limit,
            window_seconds=window_seconds,
        )
        self.subject_id = subject_id
        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after = window_seconds

    def __str__(self) -> str:
        return (
            f"rate limit exceeded for {self.subject_id}: "
            f"{self.limit} calls per {self.window_seconds}s"
        )


class CircuitOpen(Denied):
    """The circuit breaker is open; everything is refused until a human resets it."""

    def __init__(self, detail: str | None = None) -> None:
        super().__init__("circuit_open", detail=detail)
        self.detail = detail

    def __str__(self) -> str:
        return f"circuit breaker open: {self.detail or 'error rate exceeded'}"


__all__ = [
    "AgpermsError",
    "ApprovalRequired",
    "CircuitOpen",
    "ConfigurationError",
    "Denied",
    "DepthLimitExceeded",
    "ParentTokenInvalid",
    "RateLimitExceeded",
    "REASON_CIRCUIT_OPEN",
    "REASON_EXPIRED",
    "REASON_INVALID_SIGNATURE",
    "REASON_MALFORMED",
    "REASON_MISSING_TOKEN",
    "REASON_REVOKED",
    "REASON_SCOPE_NOT_GRANTED",
    "RootChainBroken",
    "ScopeEscalationDenied",
    "StorageError",
    "TokenError",
]
