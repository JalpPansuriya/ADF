"""Hash-chained, append-only audit log (PRD 8.5).

Chain construction
------------------
Each row stores ``prev_hash`` (the previous row's ``row_hash``) and
``row_hash = sha256(prev_hash + canonical_content)`` where ``canonical_content``
is a deterministic JSON serialisation of the row's semantic fields. Recomputing
the chain therefore detects any mutation of any field of any row, and any
deletion or reordering.

Single-writer design
--------------------
All appends funnel through one lock inside :class:`AuditLogger`. That is what
makes the chain safe: concurrent writers computing ``prev_hash`` from the same
tail row would produce two siblings and a fork. The lock, not the database, is
the serialisation point.

Buffering
---------
``verify_success`` is the only high-volume event and is the only one buffered --
it is appended to a queue and flushed by a background task. Every event
representing a security *decision* (mint, denial, revoke, approval, breaker
trip) is written synchronously so it is durable before the caller learns the
outcome. See DECISIONS.md 2026-08-07 (async audit buffer).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from checkpoint_service.models.audit import AuditLog
from checkpoint_service.utils import utcnow

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

# Fields that participate in the hash. Order matters and must never change
# without invalidating every existing chain.
_HASHED_FIELDS = (
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
    "event_ts",
)


def canonical_content(payload: dict[str, Any]) -> str:
    """Deterministic serialisation of the hashed fields.

    ``sort_keys`` plus a fixed separator set means the same logical row always
    hashes identically regardless of dict insertion order or Python version.
    """
    subset = {key: payload.get(key) for key in _HASHED_FIELDS}
    return json.dumps(subset, sort_keys=True, separators=(",", ":"), default=str)


def compute_row_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        (prev_hash + canonical_content(payload)).encode("utf-8")
    ).hexdigest()


@dataclass
class AuditEvent:
    """An event awaiting persistence."""

    action: str
    actor_id: str | None = None
    actor_hash: str | None = None
    jti: str | None = None
    parent_jti: str | None = None
    root_jti: str | None = None
    scopes: list[str] | None = None
    denied_scopes: list[str] | None = None
    required_scope: str | None = None
    decision: str | None = None
    reason: str | None = None
    depth: int | None = None
    detail: dict | None = None
    latency_ms: float | None = None
    event_ts: str = field(default_factory=lambda: utcnow().isoformat())

    def to_payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "actor_id": self.actor_id,
            "actor_hash": self.actor_hash,
            "jti": self.jti,
            "parent_jti": self.parent_jti,
            "root_jti": self.root_jti,
            "scopes": self.scopes,
            "denied_scopes": self.denied_scopes,
            "required_scope": self.required_scope,
            "decision": self.decision,
            "reason": self.reason,
            "depth": self.depth,
            "detail": self.detail,
            "event_ts": self.event_ts,
        }


class AuditLogger:
    """Serialised writer for the hash-chained audit log."""

    #: Event types that may be buffered. Everything else writes synchronously.
    BUFFERABLE = frozenset({"verify_success"})

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        buffer_max_size: int = 200,
        flush_interval_seconds: float = 0.5,
    ) -> None:
        self._session_factory = session_factory
        self._buffer_max_size = buffer_max_size
        self._flush_interval = flush_interval_seconds
        self._buffer: list[AuditEvent] = []
        # Guards both the buffer and the chain tail. Chain integrity depends on
        # this being the only path that computes prev_hash.
        self._lock = threading.Lock()
        self._tail_hash: str | None = None
        self._flush_task: asyncio.Task | None = None
        self._stopping = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def load_tail(self) -> str:
        """Read the current chain tip from the database."""
        with self._session_factory() as session:
            row = session.scalar(
                select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
            )
            self._tail_hash = row.row_hash if row else GENESIS_HASH
        return self._tail_hash

    async def start(self) -> None:
        """Begin the background flusher."""
        self._stopping = False
        self.load_tail()
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Flush pending events and stop the background task."""
        self._stopping = True
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._flush_task = None
        self.flush()

    async def _flush_loop(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(self._flush_interval)
                self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - defensive
                logger.exception("audit flush loop error")

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def log(self, event: AuditEvent, *, force_sync: bool = False) -> None:
        """Record an event.

        Bufferable events are queued; everything else is written before return.
        """
        if not force_sync and event.action in self.BUFFERABLE:
            with self._lock:
                self._buffer.append(event)
                should_flush = len(self._buffer) >= self._buffer_max_size
            if should_flush:
                self.flush()
            return
        self._write_batch([event])

    def flush(self) -> int:
        """Persist all buffered events. Returns the number written."""
        with self._lock:
            pending = self._buffer
            self._buffer = []
        if not pending:
            return 0
        self._write_batch(pending)
        return len(pending)

    def _write_batch(self, events: list[AuditEvent]) -> None:
        """Append events under the chain lock, in order."""
        with self._lock:
            if self._tail_hash is None:
                # Read the tail inside the lock so a concurrent writer cannot
                # observe a stale tip.
                with self._session_factory() as session:
                    row = session.scalar(
                        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
                    )
                    self._tail_hash = row.row_hash if row else GENESIS_HASH

            prev = self._tail_hash
            with self._session_factory() as session:
                for event in events:
                    payload = event.to_payload()
                    row_hash = compute_row_hash(prev, payload)
                    session.add(
                        AuditLog(
                            **payload,
                            latency_ms=event.latency_ms,
                            prev_hash=prev,
                            row_hash=row_hash,
                        )
                    )
                    prev = row_hash
                session.commit()
            self._tail_hash = prev

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------
    def verify_integrity(self, session: Session) -> tuple[bool, int, int | None, str]:
        """Walk the whole chain.

        Returns ``(intact, rows_checked, first_broken_row_id, detail)``. Detects
        field mutation, row deletion (via a ``prev_hash`` that does not match the
        preceding row's ``row_hash``) and reordering.
        """
        rows = session.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all()
        prev = GENESIS_HASH
        for index, row in enumerate(rows):
            if row.prev_hash != prev:
                return (
                    False,
                    index,
                    row.id,
                    f"row {row.id}: prev_hash does not match the previous row's row_hash "
                    "(row deleted, reordered, or prev_hash altered)",
                )
            payload = {
                "action": row.action,
                "actor_id": row.actor_id,
                "actor_hash": row.actor_hash,
                "jti": row.jti,
                "parent_jti": row.parent_jti,
                "root_jti": row.root_jti,
                "scopes": row.scopes,
                "denied_scopes": row.denied_scopes,
                "required_scope": row.required_scope,
                "decision": row.decision,
                "reason": row.reason,
                "depth": row.depth,
                "detail": row.detail,
                "event_ts": row.event_ts,
            }
            expected = compute_row_hash(prev, payload)
            if expected != row.row_hash:
                return (
                    False,
                    index,
                    row.id,
                    f"row {row.id}: content hash mismatch -- a field of this row was "
                    "modified after it was written",
                )
            prev = row.row_hash
        return True, len(rows), None, f"chain intact across {len(rows)} rows"
