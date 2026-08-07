"""Application container.

Holds the singleton engine instances and their lifecycle. Kept separate from
``main.py`` so tests can build an isolated container (SQLite + fakeredis) without
importing the ASGI app's startup behaviour.
"""

from __future__ import annotations

import logging

import redis as redis_lib
from sqlalchemy.orm import Session, sessionmaker

from checkpoint_service.config import Settings
from checkpoint_service.db import redis_client
from checkpoint_service.db.session import (
    create_all,
    get_session_factory,
    init_engine,
    session_scope,
)
from checkpoint_service.engine.audit_logger import AuditEvent, AuditLogger
from checkpoint_service.engine.delegation_engine import DelegationEngine
from checkpoint_service.engine.guardrails import (
    AnomalyDetector,
    CircuitBreaker,
    RateLimiter,
)
from checkpoint_service.engine.revocation import RevocationStore
from checkpoint_service.engine.subjects import SubjectRegistry
from checkpoint_service.engine.token_engine import TokenEngine

logger = logging.getLogger(__name__)


class AppContainer:
    """Wires the engines together and owns their lifecycle."""

    def __init__(
        self,
        settings: Settings,
        *,
        redis_override: "redis_lib.Redis | None" = None,
        create_tables: bool = False,
    ) -> None:
        self.settings = settings

        init_engine(settings.database_url)
        if create_tables:
            create_all()
        self.session_factory: sessionmaker[Session] = get_session_factory()

        redis_client.init_redis(settings.redis_url, client=redis_override)

        self.tokens = TokenEngine(settings)
        self.subjects = SubjectRegistry(settings.pii_salt, settings)
        self.revocation = RevocationStore()
        self.audit = AuditLogger(
            self.session_factory,
            buffer_max_size=settings.audit_buffer_max_size,
            flush_interval_seconds=settings.audit_flush_interval_seconds,
        )
        self.rate_limiter = RateLimiter(settings)
        self.circuit = CircuitBreaker(settings)
        self.anomaly = AnomalyDetector(settings)

        # Audit the breaker tripping. Registered as a callback rather than
        # inlined so the breaker itself stays free of persistence concerns.
        self.circuit.set_open_callback(
            lambda reason: self.audit.log(
                AuditEvent(
                    action="circuit_opened",
                    decision="deny",
                    reason=reason,
                    detail={"break_glass_endpoint": "POST /api/v1/admin/circuit/reset"},
                )
            )
        )

        self.engine = DelegationEngine(
            settings=settings,
            token_engine=self.tokens,
            revocation=self.revocation,
            audit=self.audit,
            subjects=self.subjects,
            rate_limiter=self.rate_limiter,
            circuit=self.circuit,
            anomaly=self.anomaly,
        )

    async def startup(self) -> None:
        """Rebuild caches and start the background audit writer."""
        await self.audit.start()
        with session_scope() as session:
            restored = self.revocation.rebuild_cache(session)
            expired = self.engine.expire_stale_approvals(session)
        logger.info(
            "Startup complete: %d revocations mirrored to cache, %d stale approvals expired",
            restored,
            expired,
        )

    async def shutdown(self) -> None:
        await self.audit.stop()
        redis_client.close_redis()

    def session(self) -> Session:
        return self.session_factory()
