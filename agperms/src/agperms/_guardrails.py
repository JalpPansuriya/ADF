"""Rate limiting, circuit breaking and anomaly flagging.

All three keep their state in-process by default. That is a deliberate asymmetry
with revocation: a rate limiter that forgets on restart permits one extra burst,
which is an availability nuisance. A revocation store that forgets on restart
resurrects a killed credential, which is a security failure. Different stakes,
different designs.

Every class here takes its state container by construction rather than reaching
for a module-level singleton, so two firewalls in one process are genuinely
independent.
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, Protocol

from agperms.config import Config
from agperms.errors import CircuitOpen, RateLimitExceeded

logger = logging.getLogger(__name__)


class SlidingWindowCache(Protocol):
    """A shared counter store, so limits can span processes if you want them to."""

    def hit(self, key: str, *, window_seconds: int) -> int:
        """Record one hit and return the count within the trailing window."""
        ...

    def count(self, key: str, *, window_seconds: int) -> int:
        ...

    def clear(self, prefix: str) -> None:
        ...

    def keys(self, prefix: str) -> list[str]:
        ...


class LocalWindowCache:
    """In-process sliding window. The default; no external service needed."""

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def hit(self, key: str, *, window_seconds: int) -> int:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            bucket.append(now)
            return len(bucket)

    def count(self, key: str, *, window_seconds: int) -> int:
        cutoff = time.time() - window_seconds
        with self._lock:
            bucket = self._buckets.get(key)
            if not bucket:
                return 0
            return sum(1 for ts in bucket if ts >= cutoff)

    def clear(self, prefix: str) -> None:
        with self._lock:
            for key in [k for k in self._buckets if k.startswith(prefix)]:
                del self._buckets[key]

    def keys(self, prefix: str) -> list[str]:
        with self._lock:
            return [k for k in self._buckets if k.startswith(prefix)]


class RedisWindowCache:
    """Redis-backed sliding window, for limits shared across processes.

    Uses a sorted set of timestamps rather than ``INCR``/``EXPIRE`` fixed buckets:
    fixed buckets let a caller land 2x the intended burst across a boundary, and
    for a security control that difference is worth one extra round trip.

    Requires ``agperms[redis]``.
    """

    def __init__(self, client: object, *, namespace: str = "agperms") -> None:
        self._client = client
        self._ns = namespace

    def _key(self, key: str) -> str:
        return f"{self._ns}:{key}"

    def hit(self, key: str, *, window_seconds: int) -> int:
        now = time.time()
        full = self._key(key)
        pipe = self._client.pipeline()  # type: ignore[attr-defined]
        pipe.zremrangebyscore(full, 0, now - window_seconds)
        pipe.zadd(full, {f"{now}:{uuid.uuid4().hex[:8]}": now})
        pipe.zcard(full)
        pipe.expire(full, window_seconds + 1)
        return int(pipe.execute()[2])

    def count(self, key: str, *, window_seconds: int) -> int:
        now = time.time()
        return int(
            self._client.zcount(  # type: ignore[attr-defined]
                self._key(key), now - window_seconds, now
            )
        )

    def clear(self, prefix: str) -> None:
        pattern = f"{self._key(prefix)}*"
        found = list(self._client.scan_iter(match=pattern, count=500))  # type: ignore[attr-defined]
        if found:
            self._client.delete(*found)  # type: ignore[attr-defined]

    def keys(self, prefix: str) -> list[str]:
        pattern = f"{self._key(prefix)}*"
        raw = list(self._client.scan_iter(match=pattern, count=500))  # type: ignore[attr-defined]
        strip = len(self._ns) + 1
        return [k[strip:] if isinstance(k, str) else k.decode()[strip:] for k in raw]


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
_RATE_PREFIX = "rate:"
_WINDOW_SECONDS = 60


class RateLimiter:
    """Per-agent sliding window over each guarded operation."""

    def __init__(self, config: Config, cache: SlidingWindowCache | None = None) -> None:
        self._config = config
        self._cache = cache or LocalWindowCache()

    def _limit_for(self, action: str) -> int:
        if action == "delegate":
            return self._config.rate_limit_delegate_per_min
        if action == "action":
            return self._config.rate_limit_action_per_min
        return self._config.rate_limit_verify_per_min

    def check(self, subject_id: str, action: str) -> None:
        """Consume one unit of budget, or raise :class:`RateLimitExceeded`."""
        if self._config.is_exempt(subject_id):
            return
        limit = self._limit_for(action)
        key = f"{_RATE_PREFIX}{action}:{subject_id}"
        count = self._cache.hit(key, window_seconds=_WINDOW_SECONDS)
        if count > limit:
            raise RateLimitExceeded(subject_id, limit, _WINDOW_SECONDS)

    def snapshot(self) -> dict[str, int]:
        """Current in-window counts, keyed ``<action>:<subject>``."""
        out: dict[str, int] = {}
        for key in self._cache.keys(_RATE_PREFIX):
            live = self._cache.count(key, window_seconds=_WINDOW_SECONDS)
            if live:
                out[key[len(_RATE_PREFIX) :]] = live
        return out

    def reset(self) -> None:
        self._cache.clear(_RATE_PREFIX)


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CircuitState:
    open: bool = False
    opened_at: float | None = None
    reason: str | None = None
    error_rate: float = 0.0
    samples: int = 0
    errors: int = 0


class CircuitBreaker:
    """Rolling-window error-rate breaker with a manual reset only.

    There is deliberately no automatic half-open recovery. An authorization
    component that silently re-closes hides the incident that opened it and can
    flap while the underlying fault persists, so closing it is a human decision.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._events: deque[tuple[float, bool]] = deque()
        self._lock = Lock()
        self._open = False
        self._opened_at: float | None = None
        self._reason: str | None = None
        self._on_open: Callable[[str], None] | None = None

    def set_open_callback(self, callback: Callable[[str], None]) -> None:
        """Fire ``callback`` once when the breaker trips (used for auditing)."""
        self._on_open = callback

    def record(
        self,
        *,
        error: bool,
        subject_id: str | None = None,
        policy_denial: bool = False,
    ) -> None:
        """Record one outcome, tripping the breaker if thresholds are crossed.

        ``policy_denial`` marks an error that means the firewall *worked* -- a
        blocked escalation, a refused forged token -- rather than the system
        failing. Whether those count is configurable, because counting them lets
        any client open the breaker for everyone else on purpose.
        """
        if subject_id and self._config.is_exempt(subject_id):
            return
        if policy_denial and not self._config.circuit_count_policy_denials:
            error = False

        now = time.time()
        window = self._config.circuit_window_seconds
        tripped: str | None = None

        with self._lock:
            self._events.append((now, error))
            cutoff = now - window
            while self._events and self._events[0][0] < cutoff:
                self._events.popleft()

            samples = len(self._events)
            errors = sum(1 for _, is_error in self._events if is_error)
            rate = errors / samples if samples else 0.0

            if not self._open:
                if (
                    samples >= self._config.circuit_min_samples
                    and rate >= self._config.circuit_error_rate_threshold
                ):
                    tripped = (
                        f"error_rate {rate:.0%} >= threshold "
                        f"{self._config.circuit_error_rate_threshold:.0%} "
                        f"over {samples} samples in {window}s"
                    )
                elif samples > self._config.circuit_volume_ceiling:
                    tripped = (
                        f"call volume {samples} exceeded ceiling "
                        f"{self._config.circuit_volume_ceiling} in {window}s"
                    )
                if tripped:
                    self._open = True
                    self._opened_at = now
                    self._reason = tripped

        if tripped:
            logger.error("agperms circuit breaker OPEN: %s", tripped)
            if self._on_open is not None:
                try:
                    self._on_open(tripped)
                except Exception:  # pragma: no cover - auditing must not break the breaker
                    logger.exception("circuit-open callback failed")

    def is_open(self) -> bool:
        with self._lock:
            return self._open

    def check(self) -> None:
        """Raise :class:`CircuitOpen` if the breaker is open."""
        with self._lock:
            if self._open:
                raise CircuitOpen(self._reason)

    def state(self) -> CircuitState:
        cutoff = time.time() - self._config.circuit_window_seconds
        with self._lock:
            live = [(ts, err) for ts, err in self._events if ts >= cutoff]
            samples = len(live)
            errors = sum(1 for _, err in live if err)
            return CircuitState(
                open=self._open,
                opened_at=self._opened_at,
                reason=self._reason,
                error_rate=(errors / samples) if samples else 0.0,
                samples=samples,
                errors=errors,
            )

    def reset(self) -> None:
        """Break glass: close the breaker and clear the window."""
        with self._lock:
            self._open = False
            self._opened_at = None
            self._reason = None
            self._events.clear()
        logger.warning("agperms circuit breaker manually reset")


# ---------------------------------------------------------------------------
# Anomaly flagging (log-only)
# ---------------------------------------------------------------------------
@dataclass
class _Baseline:
    intervals: deque[float] = field(default_factory=lambda: deque(maxlen=100))
    scope_counts: deque[int] = field(default_factory=lambda: deque(maxlen=100))
    last_seen: float | None = None


class AnomalyDetector:
    """Flags unusual delegation frequency or scope diversity.

    Log-only, always. An auto-blocking detector on the critical path of every
    agent action turns a false positive into an outage.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._baselines: dict[str, _Baseline] = defaultdict(_Baseline)
        self._lock = Lock()

    def observe_delegation(self, subject_id: str, scope_count: int) -> str | None:
        """Record a delegation; describe it if it looks anomalous."""
        now = time.time()
        with self._lock:
            baseline = self._baselines[subject_id]
            interval = None if baseline.last_seen is None else now - baseline.last_seen
            baseline.last_seen = now

            findings: list[str] = []
            min_samples = self._config.anomaly_min_baseline_samples
            sigma = self._config.anomaly_sigma_threshold

            if interval is not None:
                if len(baseline.intervals) >= min_samples:
                    mean, std = _mean_std(baseline.intervals)
                    # A *shorter* gap than usual is the frequency spike.
                    if _is_low_outlier(interval, mean, std, sigma):
                        findings.append(
                            f"delegation interval {interval:.3f}s is well below "
                            f"baseline mean {mean:.3f}s (std {std:.3f})"
                        )
                baseline.intervals.append(interval)

            if len(baseline.scope_counts) >= min_samples:
                mean, std = _mean_std(baseline.scope_counts)
                if _is_high_outlier(scope_count, mean, std, sigma):
                    findings.append(
                        f"requested {scope_count} scopes vs baseline mean "
                        f"{mean:.2f} (std {std:.2f})"
                    )
            baseline.scope_counts.append(scope_count)

        return "; ".join(findings) if findings else None

    def reset(self) -> None:
        with self._lock:
            self._baselines.clear()


def _mean_std(values) -> tuple[float, float]:
    data = list(values)
    if not data:
        return 0.0, 0.0
    mean = sum(data) / len(data)
    if len(data) < 2:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in data) / (len(data) - 1)
    return mean, math.sqrt(variance)


# A perfectly stable agent has std == 0, which makes the sigma test vacuous:
# `x > mean + 3*0` fires on any increase at all, and no multiple of zero can
# express "well outside normal". Both helpers fall back to a relative margin in
# that case -- otherwise the most predictable agents, whose deviations carry the
# most signal, would be the least detectable.
_ZERO_STD_RELATIVE_MARGIN = 2.0


def _is_high_outlier(value: float, mean: float, std: float, sigma: float) -> bool:
    if std > 0:
        return value > mean + sigma * std
    return value > max(mean * _ZERO_STD_RELATIVE_MARGIN, mean + 1)


def _is_low_outlier(value: float, mean: float, std: float, sigma: float) -> bool:
    if std > 0:
        return value < mean - sigma * std
    return value < mean / _ZERO_STD_RELATIVE_MARGIN


__all__ = [
    "AnomalyDetector",
    "CircuitBreaker",
    "CircuitState",
    "LocalWindowCache",
    "RateLimiter",
    "RedisWindowCache",
    "SlidingWindowCache",
]
