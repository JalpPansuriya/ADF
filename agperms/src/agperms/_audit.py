"""Hash-chained, append-only audit log.

Each row stores ``prev_hash`` and ``row_hash = sha256(prev_hash + canonical)``,
where ``canonical`` is a deterministic serialisation of the row's semantic
fields. Editing, deleting or reordering any row therefore breaks the chain from
that point onward, and the break is localisable to the first bad row.

Single writer
-------------
Every append goes through one lock. That lock, not the backing store, is what
prevents a fork: two writers computing ``prev_hash`` from the same tail would
produce two siblings, and the chain would no longer be a chain.

Everything is written synchronously. The service this was extracted from buffers
its highest-volume event for latency reasons; a library does not get to make that
tradeoff on the caller's behalf, and action records in particular must be durable
before the guarded code runs -- their *absence* is what a revoke interprets as
UNKNOWN.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any

from agperms._time import utcnow
from agperms.models import IntegrityReport
from agperms.storage.protocol import Storage

GENESIS_HASH = "0" * 64

# Fields that participate in the hash, in a fixed order. Changing this list or
# its order invalidates every previously written chain.
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

    ``sort_keys`` plus fixed separators means the same logical row hashes
    identically regardless of dict ordering or Python version.
    """
    subset = {key: payload.get(key) for key in _HASHED_FIELDS}
    return json.dumps(subset, sort_keys=True, separators=(",", ":"), default=str)


def compute_row_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        (prev_hash + canonical_content(payload)).encode("utf-8")
    ).hexdigest()


@dataclass
class AuditEvent:
    """One security-relevant event, before it is chained and persisted."""

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
    detail: dict[str, Any] | None = None
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


class AuditLog:
    """Serialised writer and verifier for the hash chain."""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage
        self._lock = threading.Lock()
        self._tail: str | None = None

    # ------------------------------------------------------------------
    def log(self, event: AuditEvent) -> None:
        """Append one event, durably, before returning."""
        self.log_batch([event])

    def log_batch(self, events: list[AuditEvent]) -> None:
        """Append several events as one atomic, correctly chained run."""
        if not events:
            return
        with self._lock:
            prev = self._tail
            if prev is None:
                prev = self._storage.audit_tail_hash() or GENESIS_HASH

            rows: list[dict[str, Any]] = []
            for event in events:
                payload = event.to_payload()
                row_hash = compute_row_hash(prev, payload)
                rows.append(
                    {
                        **payload,
                        "latency_ms": event.latency_ms,
                        "prev_hash": prev,
                        "row_hash": row_hash,
                    }
                )
                prev = row_hash

            self._storage.append_audit_batch(rows)
            self._tail = prev

    # ------------------------------------------------------------------
    def verify_integrity(self) -> IntegrityReport:
        """Walk the whole chain and report the first break, if any.

        Detects field mutation (recomputed hash differs), deletion and
        reordering (a row's ``prev_hash`` no longer matches its predecessor).
        """
        rows = self._storage.iter_audit_rows()
        prev = GENESIS_HASH
        for index, row in enumerate(rows):
            row_id = row.get("id", index + 1)
            if row.get("prev_hash") != prev:
                return IntegrityReport(
                    intact=False,
                    rows_checked=index,
                    first_broken_row_id=row_id,
                    detail=(
                        f"row {row_id}: prev_hash does not match the previous row's "
                        "row_hash (row deleted, reordered, or prev_hash altered)"
                    ),
                )
            expected = compute_row_hash(prev, row)
            if expected != row.get("row_hash"):
                return IntegrityReport(
                    intact=False,
                    rows_checked=index,
                    first_broken_row_id=row_id,
                    detail=(
                        f"row {row_id}: content hash mismatch -- a field of this row "
                        "was modified after it was written"
                    ),
                )
            prev = row["row_hash"]
        return IntegrityReport(
            intact=True,
            rows_checked=len(rows),
            first_broken_row_id=None,
            detail=f"chain intact across {len(rows)} rows",
        )


__all__ = [
    "AuditEvent",
    "AuditLog",
    "GENESIS_HASH",
    "canonical_content",
    "compute_row_hash",
]
