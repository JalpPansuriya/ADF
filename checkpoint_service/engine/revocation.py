"""Revocation store with subtree propagation (PRD 8.4).

Durability model
----------------
Postgres is the **source of truth**; Redis is a read cache rebuilt from Postgres
at startup. The PRD stored revocation state only in Redis, which fails *open*:
after a Redis restart the revocation set is empty and every previously revoked
token verifies as valid again. That inverts the system's central guarantee, so
the ordering here is deliberate -- commit to Postgres, then mirror to Redis, and
on any cache miss fall back to a Postgres read rather than concluding "not
revoked".

See DECISIONS.md 2026-08-07 (revocation durability).
"""

from __future__ import annotations

import logging
import time
from collections import deque

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from checkpoint_service.db import redis_client
from checkpoint_service.models.audit import DelegationEdge, Revocation
from checkpoint_service.utils import utcnow

logger = logging.getLogger(__name__)

REVOKED_SET_KEY = "adf:revoked"
EDGES_KEY_PREFIX = "adf:edges:"
# Sentinel proving the cache was fully populated from Postgres. Its ABSENCE is
# the signal that Redis was restarted or flushed, so an empty revocation set
# cannot be trusted to mean "nothing is revoked". Without this, a flushed cache
# silently fails open -- the exact failure mode the Postgres-truth design exists
# to prevent. Asserted by tests/test_revocation.py::
# test_revocation_survives_total_cache_loss.
CACHE_READY_KEY = "adf:cache_ready"


class RevocationStore:
    """Durable revocation with an O(1) cache path."""

    def __init__(self) -> None:
        self._degraded_logged = False

    # ------------------------------------------------------------------
    # Edge tracking
    # ------------------------------------------------------------------
    def record_edge(self, session: Session, parent_jti: str, child_jti: str) -> None:
        """Persist a parent->child edge, then mirror it into Redis.

        Called at mint time. Postgres first: if the process dies between the two
        writes, the next startup rebuild restores the Redis mirror. The reverse
        order would lose the edge permanently and orphan the child from subtree
        revocation.
        """
        session.add(DelegationEdge(parent_jti=parent_jti, child_jti=child_jti))
        try:
            session.flush()
        except IntegrityError:
            # Duplicate edge (unique constraint) -- already recorded, harmless.
            session.rollback()

        client = redis_client.get_redis()
        if client is not None and redis_client.redis_available():
            try:
                client.sadd(f"{EDGES_KEY_PREFIX}{parent_jti}", child_jti)
            except Exception as exc:  # pragma: no cover - environment dependent
                self._degrade(exc)

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def revoke_subtree(
        self, session: Session, jti: str, *, reason: str | None = None
    ) -> tuple[list[str], float]:
        """Revoke ``jti`` and every descendant.

        Returns ``(revoked_jtis, latency_ms)``. All rows are committed in one
        transaction so a partial subtree revocation is impossible -- a half-killed
        subtree would leave live tokens the operator believes are dead.
        """
        started = time.perf_counter()
        targets = self._collect_subtree(session, jti)

        already = set(
            session.scalars(
                select(Revocation.jti).where(Revocation.jti.in_(targets))
            ).all()
        )
        new_targets = [t for t in targets if t not in already]

        now = utcnow()
        for target in new_targets:
            session.add(
                Revocation(
                    jti=target,
                    revoked_at=now,
                    root_of_revocation=jti,
                    reason=reason,
                )
            )
        session.flush()
        # The caller's session_scope commits; flush here makes the rows visible
        # to any read in the same transaction.

        self._cache_add(targets)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return targets, latency_ms

    def _collect_subtree(self, session: Session, root: str) -> list[str]:
        """Breadth-first walk of the delegation edges from ``root`` inclusive.

        Uses Postgres edges rather than the Redis mirror: this runs once per
        revocation (not on the hot path) and must be correct even in degraded
        mode. ``seen`` also protects against a cycle, which should be impossible
        given depth limits but would otherwise hang the request.
        """
        seen: set[str] = {root}
        order: list[str] = [root]
        queue: deque[str] = deque([root])
        while queue:
            level = list(queue)
            queue.clear()
            children = session.scalars(
                select(DelegationEdge.child_jti).where(
                    DelegationEdge.parent_jti.in_(level)
                )
            ).all()
            for child in children:
                if child not in seen:
                    seen.add(child)
                    order.append(child)
                    queue.append(child)
        return order

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def is_revoked(self, jti: str, session: Session | None = None) -> bool:
        """O(1) cache lookup with a Postgres fallback.

        The cache is only consulted when it carries the readiness sentinel. A
        cache that lost its keyspace would otherwise report "not revoked" for
        every token -- correct-looking and catastrophically wrong. On a missing
        sentinel we read Postgres and opportunistically repair the cache.
        """
        client = redis_client.get_redis()
        if client is not None and redis_client.redis_available():
            try:
                if client.get(CACHE_READY_KEY):
                    return bool(client.sismember(REVOKED_SET_KEY, jti))
                # Cache was flushed/restarted: fall through to Postgres and
                # rebuild if we can.
                if session is not None:
                    self.rebuild_cache(session)
                    return session.get(Revocation, jti) is not None
            except Exception as exc:  # pragma: no cover - environment dependent
                self._degrade(exc)

        if session is None:
            raise RuntimeError(
                "Redis unavailable and no database session supplied for the "
                "revocation fallback; refusing to answer (would fail open)"
            )
        return session.get(Revocation, jti) is not None

    def revoked_among(self, session: Session, jtis: list[str]) -> set[str]:
        """Bulk lookup, used when rendering a delegation chain."""
        if not jtis:
            return set()
        return set(
            session.scalars(
                select(Revocation.jti).where(Revocation.jti.in_(set(jtis)))
            ).all()
        )

    # ------------------------------------------------------------------
    # Cache maintenance
    # ------------------------------------------------------------------
    def rebuild_cache(self, session: Session) -> int:
        """Repopulate Redis from Postgres. Called on every startup.

        This is what makes a Redis restart survivable.
        """
        client = redis_client.get_redis()
        if client is None or not redis_client.redis_available():
            return 0

        revoked = list(session.scalars(select(Revocation.jti)).all())
        edges = session.execute(
            select(DelegationEdge.parent_jti, DelegationEdge.child_jti)
        ).all()
        try:
            pipe = client.pipeline()
            pipe.delete(REVOKED_SET_KEY)
            if revoked:
                pipe.sadd(REVOKED_SET_KEY, *revoked)
            for parent_jti, child_jti in edges:
                pipe.sadd(f"{EDGES_KEY_PREFIX}{parent_jti}", child_jti)
            # Set the readiness sentinel LAST: until it exists, readers treat the
            # cache as untrustworthy and go to Postgres.
            pipe.set(CACHE_READY_KEY, "1")
            pipe.execute()
        except Exception as exc:  # pragma: no cover - environment dependent
            self._degrade(exc)
            return 0
        logger.info(
            "Revocation cache rebuilt: %d revoked jtis, %d edges", len(revoked), len(edges)
        )
        return len(revoked)

    def _cache_add(self, jtis: list[str]) -> None:
        client = redis_client.get_redis()
        if client is None or not redis_client.redis_available() or not jtis:
            return
        try:
            client.sadd(REVOKED_SET_KEY, *jtis)
        except Exception as exc:  # pragma: no cover - environment dependent
            self._degrade(exc)

    def _degrade(self, exc: Exception) -> None:
        redis_client.mark_unavailable()
        if not self._degraded_logged:
            logger.warning(
                "Redis error (%s); revocation lookups now fall back to Postgres", exc
            )
            self._degraded_logged = True
