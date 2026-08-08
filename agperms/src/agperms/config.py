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
from agperms.models import Reversibility, worst_of

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

#: How recoverable each default-sensitive scope is. Deliberately a *separate* map
#: from :data:`DEFAULT_SENSITIVE_SCOPES` rather than a richer replacement for it,
#: because the two answer different questions: sensitivity decides whether a
#: human must approve the grant, reversibility decides how bad it is if the
#: action goes wrong. ``spend_money`` shows why they must not be merged -- it
#: warrants an approval gate *and* is usually refundable, so it is COMPENSABLE
#: rather than IRREVERSIBLE, while ``transfer_funds`` has no clawback.
#:
#: Scopes absent from this map resolve to IRREVERSIBLE, not to a permissive
#: default. See :meth:`Config.reversibility_of`.
DEFAULT_SCOPE_REVERSIBILITY: dict[str, Reversibility] = {
    "send_email": Reversibility.IRREVERSIBLE,
    "spend_money": Reversibility.COMPENSABLE,
    "delete_data": Reversibility.IRREVERSIBLE,
    "post_public_content": Reversibility.IRREVERSIBLE,
    "transfer_funds": Reversibility.IRREVERSIBLE,
    "execute_code": Reversibility.IRREVERSIBLE,
}


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

    # --- reversibility typing ----------------------------------------------
    #: Per-scope recoverability class. A scope missing from this map is treated
    #: as IRREVERSIBLE rather than assumed safe.
    scope_reversibility: dict[str, Reversibility] = field(
        default_factory=lambda: dict(DEFAULT_SCOPE_REVERSIBILITY)
    )

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

    # Set during __post_init__ when jwt_secret was left empty and had to be
    # generated. Recorded because after generation the field is indistinguishable
    # from a caller-supplied secret, and "is this key ephemeral" is a question
    # governance scoring needs to answer honestly.
    _secret_generated: bool = field(default=False, repr=False, compare=False)

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
            object.__setattr__(self, "_secret_generated", True)
        if not self.pii_salt:
            object.__setattr__(self, "pii_salt", secrets.token_urlsafe(16))
        object.__setattr__(
            self, "sensitive_scopes", frozenset(self.sensitive_scopes)
        )
        object.__setattr__(self, "exempt_agents", frozenset(self.exempt_agents))
        # Copy so a caller mutating the dict they passed in cannot retroactively
        # change this firewall's policy. Coerce str values so a caller can pass
        # plain strings from config files.
        object.__setattr__(
            self,
            "scope_reversibility",
            {
                str(scope): Reversibility(value)
                for scope, value in self.scope_reversibility.items()
            },
        )

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

    @property
    def signing_key_is_ephemeral(self) -> bool:
        """True when no ``jwt_secret`` was supplied and one was generated.

        An ephemeral key means tokens cannot be verified after a restart or by
        another process, which is a real governance limitation rather than a
        detail -- so it stays answerable after construction.
        """
        return self._secret_generated

    def sensitive_subset(self, scopes: list[str]) -> list[str]:
        return sorted(s for s in scopes if s in self.sensitive_scopes)

    def reversibility_of(self, scope: str) -> Reversibility:
        """How recoverable ``scope`` is. Unknown scopes are IRREVERSIBLE.

        Fail closed: a scope nobody classified is more likely to be a new
        side-effecting capability than a harmless read, and mislabelling a
        dangerous action as safe is the expensive direction of the error.
        """
        return self.scope_reversibility.get(scope, Reversibility.IRREVERSIBLE)

    def worst_reversibility(self, scopes: list[str]) -> Reversibility | None:
        """The least recoverable class among ``scopes``, or ``None`` if empty."""
        return worst_of(self.reversibility_of(s) for s in scopes)

    def with_overrides(self, **changes: object) -> "Config":
        """Return a copy with ``changes`` applied (frozen-dataclass friendly)."""
        return replace(self, **changes)  # type: ignore[arg-type]


__all__ = ["Config", "DEFAULT_SCOPE_REVERSIBILITY", "DEFAULT_SENSITIVE_SCOPES"]
