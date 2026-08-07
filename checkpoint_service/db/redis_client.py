"""Redis client wiring.

Redis is a **cache and rate-limit substrate only** -- never the source of truth
for revocation. If it is unavailable the service degrades to Postgres-backed
revocation lookups (slower, still correct) rather than failing open.
"""

from __future__ import annotations

import logging

import redis

logger = logging.getLogger(__name__)

_client: redis.Redis | None = None
_available: bool = False


def init_redis(url: str, *, client: redis.Redis | None = None) -> redis.Redis | None:
    """Initialise the Redis client.

    A ``client`` may be injected (the test harness passes ``fakeredis``). Returns
    ``None`` when Redis cannot be reached, which callers must tolerate.
    """
    global _client, _available
    try:
        _client = client if client is not None else redis.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2
        )
        _client.ping()
        _available = True
    except Exception as exc:  # pragma: no cover - depends on environment
        logger.warning("Redis unavailable (%s); falling back to Postgres-only mode", exc)
        _client = None
        _available = False
    return _client


def get_redis() -> redis.Redis | None:
    return _client


def redis_available() -> bool:
    return _available and _client is not None


def mark_unavailable() -> None:
    """Flip to degraded mode after a runtime Redis error."""
    global _available
    _available = False


def close_redis() -> None:
    global _client, _available
    if _client is not None:
        try:
            _client.close()
        except Exception:  # pragma: no cover
            pass
    _client = None
    _available = False
