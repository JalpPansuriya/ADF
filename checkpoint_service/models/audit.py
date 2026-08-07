"""SQLAlchemy tables backing the audit log, revocation state and approvals.

Design notes
------------
* ``audit_log`` is append-only and hash-chained (PRD 8.5): each row stores
  ``prev_hash`` and ``row_hash = sha256(prev_hash + canonical_content)``.
* ``delegation_edge`` and ``revocation`` live in Postgres as the **source of
  truth**, with Redis used only as a read cache. The PRD put revocation solely
  in Redis; that fails *open* after a Redis restart (revoked tokens become valid
  again), which would defeat the system's headline guarantee.
* ``subject_map`` holds the opaque-UUID -> salted-hash + display-label mapping so
  tokens can carry non-identifying subjects (PRD 8.6).
"""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from checkpoint_service.models.base import Base, utcnow


class AuditLog(Base):
    """Append-only, hash-chained record of every security-relevant event."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    # Canonical ISO-8601 string of `ts`, stored verbatim because it participates
    # in the hash chain. `ts` alone is unusable for hashing: SQLite drops tzinfo
    # on round-trip, so `ts.isoformat()` after a read would not reproduce the
    # string that was hashed on write, and every integrity check would fail.
    event_ts: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Opaque subject id of the actor (never a raw human name).
    actor_id: Mapped[str | None] = mapped_column(String(200), index=True)
    # sha256(human_id + salt) when the actor is a human (PRD 8.6).
    actor_hash: Mapped[str | None] = mapped_column(String(64))
    jti: Mapped[str | None] = mapped_column(String(64), index=True)
    parent_jti: Mapped[str | None] = mapped_column(String(64), index=True)
    root_jti: Mapped[str | None] = mapped_column(String(64), index=True)
    scopes: Mapped[list | None] = mapped_column(JSON)
    denied_scopes: Mapped[list | None] = mapped_column(JSON)
    required_scope: Mapped[str | None] = mapped_column(String(128))
    decision: Mapped[str | None] = mapped_column(String(32), index=True)
    reason: Mapped[str | None] = mapped_column(String(200))
    depth: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSON)
    latency_ms: Mapped[float | None] = mapped_column(Float)

    # --- hash chain -------------------------------------------------------
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_audit_action_ts", "action", "ts"),
        Index("ix_audit_actor_ts", "actor_id", "ts"),
    )


class TokenRecord(Base):
    """Metadata for every minted token.

    Needed to reconstruct delegation trees for the dashboard and to answer
    ``/audit/chain/{jti}`` without trusting a client-supplied JWT.
    """

    __tablename__ = "token_record"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    parent_jti: Mapped[str | None] = mapped_column(String(64), index=True)
    root_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    delegation_chain: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    issued_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(200))


class DelegationEdge(Base):
    """Parent -> child edge, persisted at mint time for subtree revocation walks."""

    __tablename__ = "delegation_edge"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    child_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (UniqueConstraint("parent_jti", "child_jti", name="uq_edge"),)


class Revocation(Base):
    """Durable record of a revoked token id (source of truth for Redis cache)."""

    __tablename__ = "revocation"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    revoked_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    # jti the operator actually asked to revoke; differs from `jti` for
    # descendants killed by subtree propagation.
    root_of_revocation: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String(500))


class PendingApproval(Base):
    """A delegation held at the human-approval gate (PRD 8.2).

    No child token exists while a request sits here; the JWT is minted only when
    a human approves, so an unusable-but-signed token never circulates.
    """

    __tablename__ = "pending_approval"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    parent_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    child_agent_id: Mapped[str] = mapped_column(String(200), nullable=False)
    child_subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    sensitive_scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    # Ceiling inherited from the parent; the minted child can never outlive it.
    parent_exp: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False, index=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str | None] = mapped_column(String(200))
    child_jti: Mapped[str | None] = mapped_column(String(64), ForeignKey("token_record.jti"))
    # The minted JWT, held until the delegating agent collects it.
    child_token: Mapped[str | None] = mapped_column(Text)
    collected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class SubjectMap(Base):
    """Opaque subject id -> salted hash + display label (PRD 8.6).

    Tokens carry only ``subject_id``. The reverse mapping is access-controlled
    and never leaves the service except through admin/dashboard endpoints.
    """

    __tablename__ = "subject_map"

    subject_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    identifier_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # human | agent
    display_label: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("identifier_hash", "kind", name="uq_subject_identifier"),
    )
