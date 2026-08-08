"""Durable storage on SQLAlchemy. Requires ``agperms[sql]``.

Use this when a revocation has to outlive the process. ``MemoryStorage`` keeps
everything in RAM, which means a restart resurrects revoked capabilities -- fine
for tests, not fine for anything real.

Portability
-----------
Only backend-neutral column types are used (``JSON`` rather than ``JSONB``,
``String`` rather than ``UUID``) so the same models compile on SQLite and
Postgres. That matters because the fast test path is SQLite and the deployment
target is Postgres, and a schema that only works on one of them makes the tests
worthless as evidence.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

try:
    from sqlalchemy import (
        JSON,
        Boolean,
        DateTime,
        Float,
        Integer,
        String,
        Text,
        UniqueConstraint,
        create_engine,
        select,
    )
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
    from sqlalchemy.pool import StaticPool
except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
    raise ModuleNotFoundError(
        "agperms.storage.sql needs SQLAlchemy. Install it with:\n"
        "    pip install 'agperms[sql]'        # SQLite / any SQLAlchemy URL\n"
        "    pip install 'agperms[postgres]'   # plus the psycopg driver"
    ) from exc

from agperms._time import as_utc, utcnow
from agperms.errors import StorageError
from agperms.models import (
    ActionRecord,
    ActionReview,
    CompletionState,
    PendingApproval,
    Reversibility,
    Subject,
    TokenMetadata,
)


class _Base(DeclarativeBase):
    pass


class _Token(_Base):
    __tablename__ = "agperms_token"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    parent_jti: Mapped[str | None] = mapped_column(String(64), index=True)
    root_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    delegation_chain: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    issued_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(200))


class _Edge(_Base):
    __tablename__ = "agperms_edge"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    child_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    __table_args__ = (UniqueConstraint("parent_jti", "child_jti", name="uq_agperms_edge"),)


class _Revocation(_Base):
    __tablename__ = "agperms_revocation"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    revoked_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    root_of_revocation: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str | None] = mapped_column(String(500))


class _Subject(_Base):
    __tablename__ = "agperms_subject"

    subject_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    identifier_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    display_label: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        UniqueConstraint("identifier_hash", "kind", name="uq_agperms_subject"),
    )


class _Audit(_Base):
    __tablename__ = "agperms_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # The canonical timestamp string participates in the hash, so it is stored
    # verbatim: some backends drop tzinfo on round-trip, and a re-derived string
    # would not reproduce the bytes that were hashed on write.
    event_ts: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(200), index=True)
    actor_hash: Mapped[str | None] = mapped_column(String(64))
    jti: Mapped[str | None] = mapped_column(String(64), index=True)
    parent_jti: Mapped[str | None] = mapped_column(String(64))
    root_jti: Mapped[str | None] = mapped_column(String(64), index=True)
    scopes: Mapped[list | None] = mapped_column(JSON)
    denied_scopes: Mapped[list | None] = mapped_column(JSON)
    required_scope: Mapped[str | None] = mapped_column(String(128))
    decision: Mapped[str | None] = mapped_column(String(32), index=True)
    reason: Mapped[str | None] = mapped_column(String(500))
    depth: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSON)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class _Approval(_Base):
    __tablename__ = "agperms_approval"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    parent_jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    child_agent_id: Mapped[str] = mapped_column(String(200), nullable=False)
    child_subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    sensitive_scopes: Mapped[list] = mapped_column(JSON, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_exp: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str | None] = mapped_column(String(200))
    child_jti: Mapped[str | None] = mapped_column(String(64))
    child_token: Mapped[str | None] = mapped_column(Text)
    collected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class _Action(_Base):
    __tablename__ = "agperms_action"

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[str | None] = mapped_column(String(16))
    failure_reason: Mapped[str | None] = mapped_column(String(500))
    #: Nullable for rows written before reversibility typing existed. A NULL
    #: reads back as IRREVERSIBLE, matching the fail-closed default rather than
    #: silently reclassifying old actions as safe.
    reversibility: Mapped[str | None] = mapped_column(String(16))


class _Review(_Base):
    __tablename__ = "agperms_review"

    review_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action_name: Mapped[str] = mapped_column(String(200), nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    revoked_at: Mapped[_dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revocation_root_jti: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(200))
    reviewed_at: Mapped[_dt.datetime | None] = mapped_column(DateTime(timezone=True))


_AUDIT_FIELDS = (
    "event_ts",
    "action",
    "actor_id",
    "actor_hash",
    "jti",
    "parent_jti",
    "root_jti",
    "scopes",
    "denied_scopes",
    "required_scope",
    "decision",
    "reason",
    "depth",
    "detail",
    "latency_ms",
    "prev_hash",
    "row_hash",
)


def _is_transaction_pooler(url: str) -> bool:
    """Whether this URL points at a connection pooler in transaction mode.

    Such poolers hand a different backend connection to each transaction, which
    breaks psycopg's per-connection prepared-statement cache: you get
    ``prepared statement "_pg3_N" does not exist`` as soon as you are reassigned.
    """
    lowered = url.lower()
    return (
        "pooler.supabase.com" in lowered
        or ":6543/" in lowered
        or "pgbouncer=true" in lowered
    )


class SqlStorage:
    """Durable storage backed by SQLAlchemy."""

    durable = True

    def __init__(
        self,
        url: str = "sqlite:///agperms.db",
        *,
        create_tables: bool = True,
        echo: bool = False,
    ) -> None:
        kwargs: dict[str, Any] = {"echo": echo, "future": True}
        if url.startswith("sqlite"):
            # A single shared connection keeps an in-memory database visible to
            # every thread that touches it.
            kwargs["connect_args"] = {"check_same_thread": False}
            kwargs["poolclass"] = StaticPool
        else:
            kwargs["pool_pre_ping"] = True
            connect_args: dict[str, Any] = {}
            if _is_transaction_pooler(url):
                connect_args["prepare_threshold"] = None
                kwargs["pool_size"] = 5
                kwargs["max_overflow"] = 5
                kwargs["pool_recycle"] = 1800
            if connect_args:
                kwargs["connect_args"] = connect_args

        self._engine = create_engine(url, **kwargs)
        self._sessions = sessionmaker(bind=self._engine, expire_on_commit=False)
        if create_tables:
            _Base.metadata.create_all(self._engine)
        self._closed = False

    def _session(self) -> Session:
        if self._closed:
            raise StorageError("storage is closed")
        return self._sessions()

    # ------------------------------------------------------------------
    # Tokens
    # ------------------------------------------------------------------
    def put_token(self, metadata: TokenMetadata) -> None:
        with self._session() as session:
            session.add(
                _Token(
                    jti=metadata.jti,
                    subject_id=metadata.subject_id,
                    parent_jti=metadata.parent_jti,
                    root_jti=metadata.root_jti,
                    depth=metadata.depth,
                    max_depth=metadata.max_depth,
                    scopes=list(metadata.scopes),
                    delegation_chain=list(metadata.delegation_chain),
                    issued_at=metadata.issued_at,
                    expires_at=metadata.expires_at,
                    approval_required=metadata.approval_required,
                    approved_by=metadata.approved_by,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise StorageError(f"token {metadata.jti} already recorded") from exc

    def get_token(self, jti: str) -> TokenMetadata | None:
        with self._session() as session:
            row = session.get(_Token, jti)
            if row is None:
                return None
            return TokenMetadata(
                jti=row.jti,
                subject_id=row.subject_id,
                parent_jti=row.parent_jti,
                root_jti=row.root_jti,
                depth=row.depth,
                max_depth=row.max_depth,
                scopes=list(row.scopes),
                delegation_chain=list(row.delegation_chain),
                issued_at=as_utc(row.issued_at),  # type: ignore[arg-type]
                expires_at=as_utc(row.expires_at),  # type: ignore[arg-type]
                approval_required=row.approval_required,
                approved_by=row.approved_by,
            )

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------
    def add_edge(self, parent_jti: str, child_jti: str) -> None:
        with self._session() as session:
            session.add(_Edge(parent_jti=parent_jti, child_jti=child_jti))
            try:
                session.commit()
            except IntegrityError:
                session.rollback()  # duplicate edge carries no new information

    def children_of(self, parent_jtis: list[str]) -> list[str]:
        if not parent_jtis:
            return []
        with self._session() as session:
            return list(
                session.scalars(
                    select(_Edge.child_jti).where(_Edge.parent_jti.in_(parent_jtis))
                ).all()
            )

    def descendants_breadth_first(self, root_jti: str) -> list[str]:
        seen = {root_jti}
        order = [root_jti]
        level = [root_jti]
        while level:
            children = self.children_of(level)
            level = []
            for child in children:
                if child not in seen:
                    seen.add(child)
                    order.append(child)
                    level.append(child)
        return order

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def is_revoked(self, jti: str) -> bool:
        try:
            with self._session() as session:
                return session.get(_Revocation, jti) is not None
        except SQLAlchemyError as exc:
            # Fail closed: an unreachable store must not answer "not revoked".
            raise StorageError(f"cannot determine revocation state: {exc}") from exc

    def revoked_among(self, jtis: list[str]) -> set[str]:
        if not jtis:
            return set()
        with self._session() as session:
            return set(
                session.scalars(
                    select(_Revocation.jti).where(_Revocation.jti.in_(set(jtis)))
                ).all()
            )

    def revoke_many(
        self,
        jtis: list[str],
        *,
        root_of_revocation: str,
        reason: str | None,
        revoked_at: _dt.datetime,
    ) -> list[str]:
        already = self.revoked_among(jtis)
        fresh = [jti for jti in jtis if jti not in already]
        if not fresh:
            return []
        with self._session() as session:
            for jti in fresh:
                session.add(
                    _Revocation(
                        jti=jti,
                        revoked_at=revoked_at,
                        root_of_revocation=root_of_revocation,
                        reason=reason,
                    )
                )
            # One transaction: a half-revoked subtree would leave live tokens an
            # operator believes are dead.
            session.commit()
        return fresh

    # ------------------------------------------------------------------
    # Subjects
    # ------------------------------------------------------------------
    def get_or_create_subject(
        self, *, identifier_hash: str, kind: str, display_label: str
    ) -> Subject:
        import uuid

        with self._session() as session:
            found = session.scalar(
                select(_Subject).where(
                    _Subject.identifier_hash == identifier_hash,
                    _Subject.kind == kind,
                )
            )
            if found is not None:
                return self._to_subject(found)

            row = _Subject(
                subject_id=f"{kind}:{uuid.uuid4()}",
                identifier_hash=identifier_hash,
                kind=kind,
                display_label=display_label,
                created_at=utcnow(),
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                # Lost a race; the winner's row is the one that counts.
                session.rollback()
                found = session.scalar(
                    select(_Subject).where(
                        _Subject.identifier_hash == identifier_hash,
                        _Subject.kind == kind,
                    )
                )
                if found is None:  # pragma: no cover - should be unreachable
                    raise
                return self._to_subject(found)
            return self._to_subject(row)

    def get_subject(self, subject_id: str) -> Subject | None:
        with self._session() as session:
            row = session.get(_Subject, subject_id)
            return self._to_subject(row) if row else None

    def get_subjects(self, subject_ids: list[str]) -> dict[str, Subject]:
        if not subject_ids:
            return {}
        with self._session() as session:
            rows = session.scalars(
                select(_Subject).where(_Subject.subject_id.in_(set(subject_ids)))
            ).all()
            return {row.subject_id: self._to_subject(row) for row in rows}

    @staticmethod
    def _to_subject(row: _Subject) -> Subject:
        return Subject(
            subject_id=row.subject_id,
            identifier_hash=row.identifier_hash,
            kind=row.kind,
            display_label=row.display_label,
            created_at=as_utc(row.created_at),  # type: ignore[arg-type]
        )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def audit_tail_hash(self) -> str | None:
        with self._session() as session:
            row = session.scalar(select(_Audit).order_by(_Audit.id.desc()).limit(1))
            return row.row_hash if row else None

    def append_audit_batch(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        with self._session() as session:
            for row in rows:
                session.add(_Audit(**{key: row.get(key) for key in _AUDIT_FIELDS}))
            session.commit()

    def iter_audit_rows(self) -> list[dict[str, Any]]:
        with self._session() as session:
            rows = session.scalars(select(_Audit).order_by(_Audit.id.asc())).all()
            return [self._audit_to_dict(row) for row in rows]

    def find_audit_rows(
        self,
        *,
        action: str | None = None,
        jti: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        with self._session() as session:
            stmt = select(_Audit)
            if action is not None:
                stmt = stmt.where(_Audit.action == action)
            if jti is not None:
                stmt = stmt.where(_Audit.jti == jti)
            if limit is not None:
                stmt = stmt.order_by(_Audit.id.desc()).limit(limit)
            else:
                stmt = stmt.order_by(_Audit.id.asc())
            return [self._audit_to_dict(row) for row in session.scalars(stmt).all()]

    def count_audit_rows(self) -> int:
        with self._session() as session:
            return len(session.scalars(select(_Audit.id)).all())

    @staticmethod
    def _audit_to_dict(row: _Audit) -> dict[str, Any]:
        return {"id": row.id, **{key: getattr(row, key) for key in _AUDIT_FIELDS}}

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------
    def put_approval(self, approval: PendingApproval) -> None:
        with self._session() as session:
            session.add(self._approval_row(approval))
            session.commit()

    def get_approval(self, approval_id: str) -> PendingApproval | None:
        with self._session() as session:
            row = session.get(_Approval, approval_id)
            return self._to_approval(row) if row else None

    def update_approval(self, approval: PendingApproval) -> None:
        with self._session() as session:
            row = session.get(_Approval, approval.approval_id)
            if row is None:
                raise StorageError(f"unknown approval {approval.approval_id}")
            row.status = approval.status
            row.decided_at = approval.decided_at
            row.approved_by = approval.approved_by
            row.child_jti = approval.child_jti
            row.child_token = approval.child_token
            row.collected = approval.collected
            session.commit()

    def list_approvals(self, *, status: str | None = None) -> list[PendingApproval]:
        with self._session() as session:
            stmt = select(_Approval)
            if status is not None:
                stmt = stmt.where(_Approval.status == status)
            rows = session.scalars(stmt.order_by(_Approval.created_at.desc())).all()
            return [self._to_approval(row) for row in rows]

    @staticmethod
    def _approval_row(a: PendingApproval) -> _Approval:
        return _Approval(
            approval_id=a.approval_id,
            parent_jti=a.parent_jti,
            parent_subject_id=a.parent_subject_id,
            child_agent_id=a.child_agent_id,
            child_subject_id=a.child_subject_id,
            requested_scopes=list(a.requested_scopes),
            sensitive_scopes=list(a.sensitive_scopes),
            ttl_seconds=a.ttl_seconds,
            parent_exp=a.parent_exp,
            status=a.status,
            created_at=a.created_at,
            expires_at=a.expires_at,
            decided_at=a.decided_at,
            approved_by=a.approved_by,
            child_jti=a.child_jti,
            child_token=a.child_token,
            collected=a.collected,
        )

    @staticmethod
    def _to_approval(row: _Approval) -> PendingApproval:
        return PendingApproval(
            approval_id=row.approval_id,
            parent_jti=row.parent_jti,
            parent_subject_id=row.parent_subject_id,
            child_agent_id=row.child_agent_id,
            child_subject_id=row.child_subject_id,
            requested_scopes=tuple(row.requested_scopes),
            sensitive_scopes=tuple(row.sensitive_scopes),
            ttl_seconds=row.ttl_seconds,
            parent_exp=row.parent_exp,
            status=row.status,
            created_at=as_utc(row.created_at),  # type: ignore[arg-type]
            expires_at=as_utc(row.expires_at),  # type: ignore[arg-type]
            decided_at=as_utc(row.decided_at),
            approved_by=row.approved_by,
            child_jti=row.child_jti,
            child_token=row.child_token,
            collected=row.collected,
        )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def put_action(self, action: ActionRecord) -> None:
        with self._session() as session:
            session.add(
                _Action(
                    action_id=action.action_id,
                    jti=action.jti,
                    subject_id=action.subject_id,
                    name=action.name,
                    scope=action.scope,
                    started_at=action.started_at,
                    finished_at=action.finished_at,
                    state=action.state.value if action.state else None,
                    failure_reason=action.failure_reason,
                    reversibility=action.reversibility.value,
                )
            )
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise StorageError(
                    f"action {action.action_id} already recorded"
                ) from exc

    def close_action(
        self,
        action_id: str,
        *,
        state: CompletionState,
        finished_at: _dt.datetime,
        failure_reason: str | None,
    ) -> ActionRecord | None:
        with self._session() as session:
            row = session.get(_Action, action_id)
            if row is None:
                return None
            row.state = state.value
            row.finished_at = finished_at
            row.failure_reason = failure_reason
            session.commit()
            return self._to_action(row)

    def get_action(self, action_id: str) -> ActionRecord | None:
        with self._session() as session:
            row = session.get(_Action, action_id)
            return self._to_action(row) if row else None

    def actions_for_review(self, jtis: list[str]) -> list[ActionRecord]:
        if not jtis:
            return []
        with self._session() as session:
            rows = session.scalars(
                select(_Action)
                .where(_Action.jti.in_(set(jtis)))
                .order_by(_Action.started_at.asc())
            ).all()
        # Open (fate unknown) or closed PARTIAL. Nothing to review for a clean run.
        return [
            self._to_action(row)
            for row in rows
            if row.finished_at is None or row.state != CompletionState.CLEAN.value
        ]

    @staticmethod
    def _to_action(row: _Action) -> ActionRecord:
        return ActionRecord(
            action_id=row.action_id,
            jti=row.jti,
            subject_id=row.subject_id,
            name=row.name,
            scope=row.scope,
            started_at=as_utc(row.started_at),  # type: ignore[arg-type]
            finished_at=as_utc(row.finished_at),
            state=CompletionState(row.state) if row.state else None,
            failure_reason=row.failure_reason,
            reversibility=(
                Reversibility(row.reversibility)
                if row.reversibility
                else Reversibility.IRREVERSIBLE
            ),
        )

    # ------------------------------------------------------------------
    # Reviews
    # ------------------------------------------------------------------
    def put_review(self, review: ActionReview) -> None:
        with self._session() as session:
            session.add(
                _Review(
                    review_id=review.review_id,
                    jti=review.jti,
                    action_id=review.action_id,
                    action_name=review.action_name,
                    classification=review.classification.value,
                    revoked_at=review.revoked_at,
                    revocation_root_jti=review.revocation_root_jti,
                    reviewed=review.reviewed,
                    reviewed_by=review.reviewed_by,
                    reviewed_at=review.reviewed_at,
                )
            )
            session.commit()

    def get_review(self, review_id: str) -> ActionReview | None:
        with self._session() as session:
            row = session.get(_Review, review_id)
            return self._to_review(row) if row else None

    def update_review(self, review: ActionReview) -> None:
        with self._session() as session:
            row = session.get(_Review, review.review_id)
            if row is None:
                raise StorageError(f"unknown review {review.review_id}")
            row.reviewed = review.reviewed
            row.reviewed_by = review.reviewed_by
            row.reviewed_at = review.reviewed_at
            session.commit()

    def list_reviews(self, *, reviewed: bool | None = None) -> list[ActionReview]:
        with self._session() as session:
            stmt = select(_Review)
            if reviewed is not None:
                stmt = stmt.where(_Review.reviewed == reviewed)
            rows = session.scalars(stmt.order_by(_Review.revoked_at.desc())).all()
            return [self._to_review(row) for row in rows]

    @staticmethod
    def _to_review(row: _Review) -> ActionReview:
        return ActionReview(
            review_id=row.review_id,
            jti=row.jti,
            action_id=row.action_id,
            action_name=row.action_name,
            classification=CompletionState(row.classification),
            revoked_at=as_utc(row.revoked_at),  # type: ignore[arg-type]
            revocation_root_jti=row.revocation_root_jti,
            reviewed=row.reviewed,
            reviewed_by=row.reviewed_by,
            reviewed_at=as_utc(row.reviewed_at),
        )

    # ------------------------------------------------------------------
    def close(self) -> None:
        if not self._closed:
            self._engine.dispose()
            self._closed = True


__all__ = ["SqlStorage"]
