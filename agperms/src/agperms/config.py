"""Configuration for :class:`agperms.Firewall`.

A plain frozen dataclass rather than pydantic-settings: this is a library, and a
library should not reach into the host application's environment or read files it
was not asked to read. Every value is passed explicitly by the caller, with
defaults chosen so that ``Firewall()`` works with no arguments at all.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace

from agperms.errors import ConfigurationError

#: Scopes that require human approval before a child token is minted. Chosen as
#: a conservative default: irreversible, externally-visible, or money-moving.
DEFAULT_SENSITIVE_SCOPES: frozenset[str] = frozenset(
    {
        "send_email",
        "spend_money",
        "delete_data",
        "post_public_content",
        "transfer_funds",
        "execute_code",
    }
)


@dataclass(frozen=True)
class Config:
    """Runtime policy for a firewall instance.

    All fields have defaults. The only one you should think hard about in
    production is ``jwt_secret``: leaving it unset generates an ephemeral
    process-local key, which means tokens do not survive a restart and cannot be
    verified by another process. That is correct for tests and single-process
    embedding, and wrong for anything distributed.
    """

    # --- signing -----------------------------------------------------------
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    issuer: str = "agperms"

    # --- token policy ------------------------------------------------------
    max_delegation_depth: int = 5
    default_ttl_seconds: int = 3600
    max_ttl_seconds: int = 86_400

    # --- privacy -----------------------------------------------------------
    #: Salt for hashing human-linked identifiers before they are persisted.
    #: Rotating this orphans every existing subject mapping -- treat it as a data
    #: migration, not a config tweak.
    pii_salt: str = ""

    # --- approval gate -----------------------------------------------------
    sensitive_scopes: frozenset[str] = DEFAULT_SENSITIVE_SCOPES
    approval_timeout_seconds: int = 300

    # --- rate limiting -----------------------------------------------------
    rate_limit_delegate_per_min: int = 60
    rate_limit_verify_per_min: int = 300
    #: Budget for action checkpoints. Generous because a checkpoint is cheap and
    #: throttling it would silently create UNKNOWN classifications, which is
    #: worse than the traffic it would save.
    rate_limit_action_per_min: int = 600

    # --- circuit breaker ---------------------------------------------------
    circuit_window_seconds: int = 60
    circuit_error_rate_threshold: float = 0.25
    circuit_min_samples: int = 20
    circuit_volume_ceiling: int = 10_000
    #: Whether denials that represent the firewall *working* (blocked escalation,
    #: forged token) count toward the breaker's error rate. Defaults to False:
    #: counting them lets any client open the breaker for everyone else just by
    #: spamming requests that are correctly refused.
    circuit_count_policy_denials: bool = False

    # --- anomaly flagging (log-only, never blocks) -------------------------
    anomaly_sigma_threshold: float = 3.0
    anomaly_min_baseline_samples: int = 10

    # --- guardrail exemption ----------------------------------------------
    #: Agents exempt from rate limiting and breaker accounting. An entry here is
    #: an unthrottled identity; keep it empty outside benchmarks.
    exempt_agents: frozenset[str] = frozenset()

    # Resolved at runtime: opaque subject ids that map back to an exempt agent
    # name. Tokens carry ``agent:<uuid>`` subjects, so the raw name in
    # ``exempt_agents`` would never match without this indirection.
    _exempt_subject_ids: set[str] = field(
        default_factory=set, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if self.max_delegation_depth < 1:
            raise ConfigurationError("max_delegation_depth must be >= 1")
        if not 0.0 < self.circuit_error_rate_threshold <= 1.0:
            raise ConfigurationError(
                "circuit_error_rate_threshold must be in (0, 1]"
            )
        if self.default_ttl_seconds <= 0 or self.max_ttl_seconds <= 0:
            raise ConfigurationError("ttl values must be positive")
        if self.jwt_algorithm not in {"HS256", "HS384", "HS512"}:
            raise ConfigurationError(
                f"unsupported jwt_algorithm {self.jwt_algorithm!r}; "
                "agperms signs with HMAC (HS256/384/512)"
            )
        # Frozen dataclass: use object.__setattr__ to fill generated defaults.
        if not self.jwt_secret:
            object.__setattr__(self, "jwt_secret", secrets.token_urlsafe(48))
        if not self.pii_salt:
            object.__setattr__(self, "pii_salt", secrets.token_urlsafe(16))
        object.__setattr__(
            self, "sensitive_scopes", frozenset(self.sensitive_scopes)
        )
        object.__setattr__(self, "exempt_agents", frozenset(self.exempt_agents))

    # ------------------------------------------------------------------
    def is_exempt(self, agent_id: str | None) -> bool:
        """True if this subject bypasses rate limiting and breaker accounting.

        Matches either the configured raw name or an opaque subject id that has
        been resolved from one.
        """
        if not agent_id:
            return False
        return agent_id in self.exempt_agents or agent_id in self._exempt_subject_ids

    def register_exempt_subject(self, raw_identifier: str, subject_id: str) -> None:
        """Record that ``subject_id`` resolves from an exempt raw identifier."""
        if raw_identifier in self.exempt_agents:
            self._exempt_subject_ids.add(subject_id)

    def is_sensitive(self, scope: str) -> bool:
        return scope in self.sensitive_scopes

    def sensitive_subset(self, scopes: list[str]) -> list[str]:
        return sorted(s for s in scopes if s in self.sensitive_scopes)

    def with_overrides(self, **changes: object) -> "Config":
        """Return a copy with ``changes`` applied (frozen-dataclass friendly)."""
        return replace(self, **changes)  # type: ignore[arg-type]


__all__ = ["Config", "DEFAULT_SENSITIVE_SCOPES"]
