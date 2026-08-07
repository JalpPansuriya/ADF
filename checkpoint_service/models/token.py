"""Pydantic schemas for the capability token and the public API surface.

The JWT payload mirrors PRD Section 5 with one deliberate deviation: every
identity field carries an **opaque subject UUID** rather than a human-readable
name (``human:3f9a...`` not ``human:jalp``). PRD 8.6 requires opaque identifiers
wherever a token crosses a trust boundary, and a capability token crosses one by
definition. The UUID -> display-label / salted-hash mapping lives server-side in
the access-controlled ``subject_map`` table.
"""

from __future__ import annotations

import datetime as _dt
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ScopeList = Annotated[list[str], Field(min_length=1)]


class DelegationChainEntry(BaseModel):
    """One hop in the chain of custody, oldest (root) first."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(description="Opaque subject id of the granting party")
    jti: str = Field(description="Token id held by that party at grant time")
    scopes: list[str] = Field(description="Scopes that party held at grant time")
    ts: str = Field(description="ISO-8601 timestamp of the grant")


class TokenClaims(BaseModel):
    """Decoded JWT claims (PRD Section 5)."""

    model_config = ConfigDict(extra="forbid")

    jti: str
    sub: str
    iss: str
    issued_for: str
    scopes: list[str]
    delegation_chain: list[DelegationChainEntry] = Field(default_factory=list)
    depth: int
    max_depth: int
    iat: int
    exp: int
    approval_required: bool = False
    approved_by: str | None = None
    root_jti: str = Field(description="jti of the root token this chain terminates at")

    @property
    def scope_set(self) -> frozenset[str]:
        return frozenset(self.scopes)

    @property
    def expires_at(self) -> _dt.datetime:
        return _dt.datetime.fromtimestamp(self.exp, tz=_dt.timezone.utc)

    @property
    def is_root(self) -> bool:
        return self.depth == 0


# --------------------------------------------------------------------------
# Request / response bodies
# --------------------------------------------------------------------------
class RootTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    human_id: str = Field(min_length=1, max_length=200)
    scopes: ScopeList
    ttl_seconds: int = Field(default=3600, gt=0)
    # PRD Section 5 calls max_depth "copied from root config" but Section 6.1
    # defines no field for it. Exposed as an optional per-root override that
    # falls back to ADF_MAX_DELEGATION_DEPTH; immutable in all descendants.
    max_depth: int | None = Field(default=None, ge=1, le=32)

    @field_validator("scopes")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return _normalise_scopes(value)


class RootTokenResponse(BaseModel):
    token: str
    jti: str
    subject_id: str
    scopes: list[str]
    max_depth: int
    expires_at: str


class DelegateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    child_agent_id: str = Field(min_length=1, max_length=200)
    requested_scopes: ScopeList
    ttl_seconds: int = Field(default=600, gt=0)

    @field_validator("requested_scopes")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return _normalise_scopes(value)


class DelegateResponse(BaseModel):
    token: str
    jti: str
    subject_id: str
    scopes: list[str]
    depth: int
    expires_at: str
    approval_required: bool = False
    approved_by: str | None = None


class PendingApprovalResponse(BaseModel):
    status: Literal["pending_approval"] = "pending_approval"
    approval_id: str
    message: str
    requested_scopes: list[str]
    sensitive_scopes: list[str]
    expires_at: str


class ScopeEscalationError(BaseModel):
    """Body of the 403 returned on an over-privileged delegation (PRD 6.2)."""

    error: Literal["scope_escalation_denied"] = "scope_escalation_denied"
    requested: list[str]
    allowed_max: list[str]
    denied_scopes: list[str]


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1)
    required_scope: str = Field(min_length=1)


class VerifyResponse(BaseModel):
    valid: Literal[True] = True
    agent_id: str
    jti: str
    remaining_scopes: list[str]
    depth: int
    expires_at: str


class VerifyFailure(BaseModel):
    valid: Literal[False] = False
    reason: str


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    jti: str = Field(min_length=1)
    reason: str | None = Field(default=None, max_length=500)


class RevokeResponse(BaseModel):
    revoked: bool
    subtree_count: int
    revoked_jtis: list[str]
    latency_ms: float


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1)
    decision: Literal["approve", "deny"] | None = None
    approver_id: str = Field(default="human:admin", max_length=200)


class ApprovalDecisionResponse(BaseModel):
    approval_id: str
    status: str
    child_jti: str | None = None
    scopes: list[str] | None = None
    message: str


class PendingTokenResponse(BaseModel):
    """Result of the agent polling for an approved token.

    ``status`` is one of pending / approved / denied / expired. The JWT is
    present only when approved, and is returned once the delegating agent
    collects it.
    """

    approval_id: str
    status: str
    token: str | None = None
    jti: str | None = None
    scopes: list[str] | None = None
    expires_at: str | None = None
    message: str


class ChainEntryOut(BaseModel):
    agent_id: str
    display_label: str | None = None
    jti: str
    scopes: list[str]
    ts: str
    depth: int
    revoked: bool = False
    expired: bool = False


class ChainResponse(BaseModel):
    jti: str
    depth: int
    chain: list[ChainEntryOut]
    scopes: list[str]
    revoked: bool
    expired: bool


class IntegrityResponse(BaseModel):
    intact: bool
    rows_checked: int
    first_broken_row_id: int | None = None
    detail: str


def _normalise_scopes(value: list[str]) -> list[str]:
    """Strip, reject blanks, de-duplicate, and sort for canonical comparison."""
    cleaned: list[str] = []
    for scope in value:
        scope = scope.strip()
        if not scope:
            raise ValueError("scopes must not contain empty strings")
        if scope not in cleaned:
            cleaned.append(scope)
    return sorted(cleaned)
