"""Database engine/session management.

SQLite support exists purely so the eval harness runs without Docker; Postgres
is the production target. The ``check_same_thread``/``StaticPool`` handling below
is required because FastAPI's TestClient runs endpoint code on a worker thread
while the test body holds the same in-memory database.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from checkpoint_service.models.base import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _is_transaction_pooler(url: str) -> bool:
    """Heuristic: is this a connection-multiplexing pooler in transaction mode?

    Supabase's pooler (``*.pooler.supabase.com``) and PgBouncer conventionally
    listen on 6543 in transaction mode, where each transaction may land on a
    different backend connection. Server-side prepared statements are scoped to a
    backend, so a client that caches them observes
    ``prepared statement "_pg3_N" does not exist`` or ``already exists`` as soon
    as it is routed elsewhere -- which is exactly what happened against Supabase.
    """
    lowered = url.lower()
    return (
        "pooler.supabase.com" in lowered
        or ":6543/" in lowered
        or "pgbouncer=true" in lowered
    )


def init_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create (or replace) the process-wide engine and session factory."""
    global _engine, _SessionLocal

    kwargs: dict = {"echo": echo, "future": True}
    if _is_sqlite(database_url):
        kwargs["connect_args"] = {"check_same_thread": False}
        # A single shared connection keeps ``sqlite:///:memory:`` visible to both
        # the test thread and the TestClient's worker thread.
        kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_pre_ping"] = True
        connect_args: dict = {"connect_timeout": 30}
        if _is_transaction_pooler(database_url):
            # Disable psycopg's prepared-statement cache. Without this every
            # INSERT eventually fails once the pooler reassigns the connection.
            connect_args["prepare_threshold"] = None
            # The pooler already multiplexes, so a large client-side pool adds
            # little; keep it modest and recycle to avoid stale handles.
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 5
            kwargs["pool_recycle"] = 1800
        kwargs["connect_args"] = connect_args

    engine = create_engine(database_url, **kwargs)

    if _is_sqlite(database_url):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _engine = engine
    _SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database engine not initialised; call init_engine() first")
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        raise RuntimeError("Session factory not initialised; call init_engine() first")
    return _SessionLocal


def create_all() -> None:
    """Create tables directly (used by tests and first-run bootstrap).

    Production migrations are managed by Alembic; this is the fast path.
    """
    Base.metadata.create_all(bind=get_engine())


def drop_all() -> None:
    Base.metadata.drop_all(bind=get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on exception."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    with session_scope() as session:
        yield session


def dispose_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
