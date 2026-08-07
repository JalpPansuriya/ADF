"""Configuration for the Checkpoint Service.

Security posture: there are NO insecure defaults for secrets. If
``ADF_ADMIN_API_KEY`` or ``ADF_JWT_SECRET`` are absent, blank, or still set to
a ``change-me`` placeholder, :func:`get_settings` raises and the app refuses to
boot. A service that silently starts with a guessable signing key is worse than
one that fails loudly.
"""

from __future__ import annotations

import functools
import pathlib
from typing import Any

import yaml
from pydantic import Field, PrivateAttr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SENSITIVE_SCOPES_FILE = REPO_ROOT / "sensitive_scopes.yaml"

_PLACEHOLDER_PREFIXES = ("change-me", "changeme", "your-", "todo", "xxx")


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or unsafe."""


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return any(lowered.startswith(p) for p in _PLACEHOLDER_PREFIXES)


class Settings(BaseSettings):
    """Runtime settings, all overridable by ``ADF_``-prefixed env vars."""

    model_config = SettingsConfigDict(
        env_prefix="ADF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- secrets (no defaults; validated below) ---------------------------
    admin_api_key: str = ""
    jwt_secret: str = ""
    pii_salt: str = ""

    # --- infrastructure ---------------------------------------------------
    database_url: str = "postgresql+psycopg://adf:adf@localhost:5432/adf"
    redis_url: str = "redis://localhost:6379/0"

    # --- token policy -----------------------------------------------------
    jwt_algorithm: str = "HS256"
    issuer: str = "checkpoint-service"
    max_delegation_depth: int = 5
    root_default_ttl_seconds: int = 3600
    max_ttl_seconds: int = 86400

    # --- guardrails: rate limiting (PRD 8.1) ------------------------------
    rate_limit_delegate_per_min: int = 60
    rate_limit_verify_per_min: int = 300

    # --- guardrails: circuit breaker (PRD 8.3) ----------------------------
    circuit_window_seconds: int = 60
    circuit_error_rate_threshold: float = 0.25
    circuit_min_samples: int = 20
    circuit_volume_ceiling: int = 10_000
    # PRD 8.3 counts "verify failures + delegate rejections" toward the error
    # rate. That has a sharp edge: a client flooding deliberately over-privileged
    # delegations drives the rate to 100% and opens the breaker for every other
    # agent -- the firewall doing its job correctly becomes a denial-of-service
    # vector. Default follows the PRD; set false to count only faults that
    # indicate genuine system distress. See DECISIONS.md 2026-08-07.
    circuit_count_policy_denials: bool = True

    # --- guardrails: approval gate (PRD 8.2) ------------------------------
    approval_timeout_seconds: int = 300

    # --- guardrails: anomaly detection (PRD 8.7) --------------------------
    anomaly_sigma_threshold: float = 3.0
    anomaly_min_baseline_samples: int = 10

    # Agents exempt from rate limiting and circuit-breaker accounting. Used so
    # the item-8 latency benchmark measures the real code path (auth, decode,
    # revocation lookup, audit) rather than the rate limiter.
    guardrail_exempt_agents: list[str] = Field(default_factory=list)

    # --- audit log --------------------------------------------------------
    # verify_success events are buffered and flushed by a single background
    # writer; every other event type is written synchronously. See PRD
    # deviation note in the README.
    audit_buffer_max_size: int = 200
    audit_flush_interval_seconds: float = 0.5

    # --- misc -------------------------------------------------------------
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    enforce_secret_strength: bool = True

    #: Opaque subject ids resolved from an exempt raw identifier. Populated at
    #: runtime by SubjectRegistry; not settable via env.
    _exempt_subject_ids: set[str] = PrivateAttr(default_factory=set)

    @field_validator("guardrail_exempt_agents", "cors_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: Any) -> Any:
        """Allow comma-separated env values for list fields."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("circuit_error_rate_threshold")
    @classmethod
    def _check_rate(cls, value: float) -> float:
        if not 0.0 < value <= 1.0:
            raise ValueError("circuit_error_rate_threshold must be in (0, 1]")
        return value

    # ------------------------------------------------------------------
    def validate_secrets(self) -> None:
        """Fail loudly on missing or placeholder secrets."""
        problems: list[str] = []
        for name, value, min_len in (
            ("ADF_ADMIN_API_KEY", self.admin_api_key, 16),
            ("ADF_JWT_SECRET", self.jwt_secret, 32),
            ("ADF_PII_SALT", self.pii_salt, 8),
        ):
            if not value:
                problems.append(f"{name} is not set")
                continue
            if not self.enforce_secret_strength:
                continue
            if _looks_like_placeholder(value):
                problems.append(f"{name} still looks like a placeholder value")
            elif len(value) < min_len:
                problems.append(f"{name} must be at least {min_len} characters")
        if problems:
            raise ConfigurationError(
                "Refusing to start with unsafe configuration:\n  - "
                + "\n  - ".join(problems)
                + "\nSee .env.example. Generate secrets with: "
                'python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )

    @functools.cached_property
    def sensitive_scopes(self) -> frozenset[str]:
        """Scopes requiring human approval, loaded from sensitive_scopes.yaml."""
        return load_sensitive_scopes(SENSITIVE_SCOPES_FILE)

    def is_exempt(self, agent_id: str | None) -> bool:
        """True if this subject bypasses rate limiting and breaker accounting.

        Matches either the raw configured name or an opaque subject id that has
        been resolved from one. Tokens carry ``agent:<uuid>`` subjects (PRD 8.6),
        which are unknowable at config-authoring time, so
        :class:`~checkpoint_service.engine.subjects.SubjectRegistry` registers the
        mapping here as it resolves identifiers. Without this indirection the
        exempt list could never match anything and the item-8 benchmark would be
        measuring the rate limiter.
        """
        if not agent_id:
            return False
        return agent_id in set(self.guardrail_exempt_agents) or agent_id in self._exempt_subject_ids

    def register_exempt_subject(self, raw_identifier: str, subject_id: str) -> None:
        """Record that ``subject_id`` resolves from an exempt raw identifier."""
        if raw_identifier in set(self.guardrail_exempt_agents):
            self._exempt_subject_ids.add(subject_id)


def load_sensitive_scopes(path: pathlib.Path) -> frozenset[str]:
    """Read the sensitive-scope list from YAML.

    A missing file is treated as an empty list rather than an error so the
    library remains importable in bare test environments, but a malformed file
    is a hard error -- silently ignoring it would disable the approval gate.
    """
    if not path.exists():
        return frozenset()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigurationError(f"{path} must contain a YAML mapping")
    scopes = raw.get("sensitive_scopes", [])
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        raise ConfigurationError(f"{path}: 'sensitive_scopes' must be a list of strings")
    return frozenset(scopes)


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton (validated)."""
    settings = Settings()
    settings.validate_secrets()
    return settings


def reset_settings_cache() -> None:
    """Clear the settings cache. Used by tests that patch the environment."""
    get_settings.cache_clear()
