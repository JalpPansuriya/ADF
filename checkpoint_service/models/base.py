"""SQLAlchemy declarative base and shared column helpers.

Portability note: every column type used across these models is deliberately
backend-neutral (``JSON`` rather than Postgres ``JSONB``, ``String`` rather than
``UUID``). The eval harness runs against SQLite for speed while production runs
Postgres, so the schema must be expressible on both.
"""

from __future__ import annotations

import datetime as _dt

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all ADF tables."""


def utcnow() -> _dt.datetime:
    """Timezone-aware UTC now.

    Stored naive-in-UTC by SQLAlchemy on backends without tz support, so all
    comparisons in this codebase go through :func:`checkpoint_service.utils.as_utc`.
    """
    return _dt.datetime.now(_dt.timezone.utc)
