"""Small shared helpers: time normalisation and PII hashing."""

from __future__ import annotations

import datetime as _dt
import hashlib


def utcnow() -> _dt.datetime:
    """Current time as a timezone-aware UTC datetime."""
    return _dt.datetime.now(_dt.timezone.utc)


def utcnow_ts() -> int:
    """Current time as an integer UNIX timestamp (JWT ``iat``/``exp`` form)."""
    return int(utcnow().timestamp())


def as_utc(value: _dt.datetime | None) -> _dt.datetime | None:
    """Coerce a possibly-naive datetime to timezone-aware UTC.

    SQLite (used by the test harness) drops tzinfo on round-trip, so any
    datetime read back from the database must pass through here before being
    compared against :func:`utcnow`. Without this, expiry checks raise
    ``TypeError: can't compare offset-naive and offset-aware datetimes``.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc)


def iso(value: _dt.datetime) -> str:
    """ISO-8601 rendering with an explicit UTC offset."""
    coerced = as_utc(value)
    assert coerced is not None
    return coerced.isoformat()


def from_ts(ts: int | float) -> _dt.datetime:
    """Build a UTC datetime from a UNIX timestamp."""
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc)


def hash_identifier(identifier: str, salt: str) -> str:
    """``sha256(identifier + salt)`` hex digest, per PRD 8.6.

    Used before persisting any human-linked identifier into the audit log. The
    reversible mapping lives in the access-controlled ``subject_map`` table.
    """
    return hashlib.sha256(f"{identifier}{salt}".encode("utf-8")).hexdigest()
