"""agperms -- capability narrowing and in-flight revocation forensics for AI agents.

Two things this library does that a plain permission check does not:

**Narrowing is enforced, not requested.** A delegated capability can only ever be
a subset of the one it came from. The check runs against the freshly verified
parent token, so a stale record or a caller's own claim cannot widen a grant.

**Revocation tells you what was mid-flight.** Wrap side-effecting work in
``fw.action(...)`` and a revoke reports whether each open action was CLEAN,
PARTIAL, or UNKNOWN -- instead of only telling you the token stopped working and
leaving you to guess what the agent had already done.

Quick start::

    from agperms import Firewall

    fw = Firewall()
    root = fw.mint_root(subject="alice", scopes=["read_calendar", "send_email"])
    child = fw.delegate(root.token, to="email-agent", scopes=["send_email"])

    with fw.action(child.token, scope="send_email", name="welcome"):
        send_email(draft)

    result = fw.revoke(root.jti)
    for review in result.reviews:
        print(review.action_name, review.classification)

The default ``Firewall()`` uses in-memory storage and an ephemeral signing key --
correct for tests and single-process embedding, wrong for anything that must
survive a restart. See the README for the durable setup.
"""

from __future__ import annotations

from agperms.config import (
    DEFAULT_SCOPE_REVERSIBILITY,
    DEFAULT_SENSITIVE_SCOPES,
    Config,
)
from agperms.errors import (
    AgpermsError,
    ApprovalRequired,
    CircuitOpen,
    ConfigurationError,
    Denied,
    DepthLimitExceeded,
    ParentTokenInvalid,
    RateLimitExceeded,
    RootChainBroken,
    ScopeEscalationDenied,
    StorageError,
    TokenError,
)
from agperms.firewall import (
    ActionHandle,
    Firewall,
    classify_action,
    review_priority,
)
from agperms.models import (
    ActionRecord,
    ActionReview,
    Capability,
    ChainHop,
    CompletionState,
    DelegationChainEntry,
    IntegrityReport,
    PendingApproval,
    RevocationResult,
    Reversibility,
    TokenClaims,
    TokenMetadata,
    VerifyResult,
)
from agperms.risk import PERMISSION_WEIGHTS, RiskState, compute_risk_state
from agperms.storage.memory import MemoryStorage

__version__ = "0.1.0"

__all__ = [
    "ActionHandle",
    "ActionRecord",
    "ActionReview",
    "AgpermsError",
    "ApprovalRequired",
    "Capability",
    "ChainHop",
    "CircuitOpen",
    "CompletionState",
    "Config",
    "ConfigurationError",
    "DEFAULT_SCOPE_REVERSIBILITY",
    "DEFAULT_SENSITIVE_SCOPES",
    "DelegationChainEntry",
    "Denied",
    "DepthLimitExceeded",
    "Firewall",
    "IntegrityReport",
    "MemoryStorage",
    "PERMISSION_WEIGHTS",
    "ParentTokenInvalid",
    "PendingApproval",
    "RateLimitExceeded",
    "RevocationResult",
    "Reversibility",
    "RiskState",
    "RootChainBroken",
    "ScopeEscalationDenied",
    "StorageError",
    "TokenClaims",
    "TokenError",
    "TokenMetadata",
    "VerifyResult",
    "__version__",
    "classify_action",
    "compute_risk_state",
    "review_priority",
]
