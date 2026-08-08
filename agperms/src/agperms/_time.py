"""Time normalisation and PII hashing helpers."""

from __future__ import annotations

import datetime as _dt
import hashlib

_UTC = _dt.timezone.utc


def utcnow() -> _dt.datetime:
    """Current time as a timezone-aware UTC datetime."""
    return _dt.datetime.now(_UTC)


def utcnow_ts() -> int:
    """Current time as an integer UNIX timestamp (JWT ``iat``/``exp`` form)."""
    return int(utcnow().timestamp())


def as_utc(value: _dt.datetime | None) -> _dt.datetime | None:
    """Coerce a possibly-naive datetime to timezone-aware UTC.

    Some backends (SQLite notably) drop tzinfo on round-trip, so any datetime
    read back from storage must pass through here before being compared against
    :func:`utcnow`. Without it, expiry checks raise ``TypeError: can't compare
    offset-naive and offset-aware datetimes``.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=_UTC)
    return value.astimezone(_UTC)


def iso(value: _dt.datetime) -> str:
    """ISO-8601 rendering with an explicit UTC offset."""
    coerced = as_utc(value)
    assert coerced is not None
    return coerced.isoformat()


def from_ts(ts: int | float) -> _dt.datetime:
    """Build a UTC datetime from a UNIX timestamp."""
    return _dt.datetime.fromtimestamp(ts, tz=_UTC)


def hash_identifier(identifier: str, salt: str) -> str:
    """``sha256(identifier + salt)`` hex digest.

    Applied before persisting any human-linked identifier, so the durable record
    never contains a raw name. The reversible mapping lives in the subject store
    and is only exposed through an explicit lookup.
    """
    return hashlib.sha256(f"{identifier}{salt}".encode("utf-8")).hexdigest()


def truncate_reason(text: str, limit: int = 200) -> str:
    """Clamp a free-text reason before it enters the append-only audit chain.

    Exception messages land in an immutable log, so an unbounded message is both
    a storage and a disclosure problem. Callers should still avoid putting
    secrets in exception text -- truncation limits the blast radius, it does not
    sanitise.
    """
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "\u2026"
