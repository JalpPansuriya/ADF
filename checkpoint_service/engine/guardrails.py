"""Guardrails: rate limiting, circuit breaker, approval gate, anomaly flag.

All four degrade gracefully without Redis by falling back to in-process state.
That is acceptable here in a way it is *not* for revocation: a rate limiter that
resets on restart permits a burst, while a revocation store that resets on
restart resurrects a killed credential. The former is a availability nuisance,
the latter is a security failure -- hence the different designs.
"""

from __future__ import annotations

import logging
import math
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock

from checkpoint_service.config import Settings
from checkpoint_service.db import redis_client

logger = logging.getLogger(__name__)

RATE_KEY_PREFIX = "adf:rate:"
CIRCUIT_KEY = "adf:circuit"


class RateLimitExceeded(Exception):
    """Raised when an agent exceeds its sliding-window budget."""

    def __init__(self, subject_id: str, limit: int, window_seconds: int) -> None:
        super().__init__(
            f"rate limit exceeded for {subject_id}: {limit} calls per {window_seconds}s"
        )
        self.subject_id = subject_id
        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after = window_seconds


class CircuitOpen(Exception):
    """Raised when the breaker is open (PRD 8.3)."""


# ---------------------------------------------------------------------------
# Rate limiting (PRD 8.1)
# ---------------------------------------------------------------------------
class RateLimiter:
    """Per-agent sliding window.

    Redis path uses a sorted set of request timestamps, which is a true sliding
    window rather than the fixed buckets an ``INCR``/``EXPIRE`` pair produces.
    Fixed buckets allow 2x the intended burst across a boundary; for a security
    control that difference is worth the extra Redis round trip.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._local: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, subject_id: str, action: str) -> None:
        """Consume one unit of budget. Raises :class:`RateLimitExceeded`."""
        if self._settings.is_exempt(subject_id):
            return

        limit = (
            self._settings.rate_limit_delegate_per_min
            if action == "delegate"
            else self._settings.rate_limit_verify_per_min
        )
        window = 60
        now = time.time()
        key = f"{RATE_KEY_PREFIX}{action}:{subject_id}"

        client = redis_client.get_redis()
        if client is not None and redis_client.redis_available():
            try:
                pipe = client.pipeline()
                pipe.zremrangebyscore(key, 0, now - window)
                pipe.zadd(key, {f"{now}:{uuid.uuid4().hex[:8]}": now})
                pipe.zcard(key)
                pipe.expire(key, window + 1)
                count = pipe.execute()[2]
                if count > limit:
                    raise RateLimitExceeded(subject_id, limit, window)
                return
            except RateLimitExceeded:
                raise
            except Exception as exc:  # pragma: no cover - environment dependent
                redis_client.mark_unavailable()
                logger.warning("Redis rate-limit error (%s); using in-process window", exc)

        with self._lock:
            bucket = self._local[key]
            cutoff = now - window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            bucket.append(now)
            count = len(bucket)
        if count > limit:
            raise RateLimitExceeded(subject_id, limit, window)

    def snapshot(self) -> dict[str, int]:
        """Current in-window counts per key (dashboard/system-health view)."""
        now = time.time()
        cutoff = now - 60
        out: dict[str, int] = {}
        client = redis_client.get_redis()
        if client is not None and redis_client.redis_available():
            try:
                for key in client.scan_iter(match=f"{RATE_KEY_PREFIX}*", count=200):
                    out[key.replace(RATE_KEY_PREFIX, "")] = int(
                        client.zcount(key, cutoff, now)
                    )
                return out
            except Exception:  # pragma: no cover
                redis_client.mark_unavailable()
        with self._lock:
            for key, bucket in self._local.items():
                live = sum(1 for ts in bucket if ts >= cutoff)
                if live:
                    out[key.replace(RATE_KEY_PREFIX, "")] = live
        return out

    def reset(self) -> None:
        """Clear all windows. Test/break-glass helper."""
        with self._lock:
            self._local.clear()
        client = redis_client.get_redis()
        if client is not None and redis_client.redis_available():
            try:
                keys = list(client.scan_iter(match=f"{RATE_KEY_PREFIX}*", count=500))
                if keys:
                    client.delete(*keys)
            except Exception:  # pragma: no cover
                redis_client.mark_unavailable()


# ---------------------------------------------------------------------------
# Circuit breaker (PRD 8.3)
# ---------------------------------------------------------------------------
@dataclass
class CircuitState:
    open: bool = False
    opened_at: float | None = None
    reason: str | None = None
    error_rate: float = 0.0
    samples: int = 0
    errors: int = 0
    volume: int = 0


class CircuitBreaker:
    """Rolling-window error-rate breaker with a manual break-glass reset.

    Deliberately has no automatic half-open recovery: PRD 8.3 specifies that
    while open, only a human "break glass" call may reset it. Auto-recovery in an
    authorization service risks flapping between open and closed while an attack
    or outage is ongoing, and hides the incident from the operator.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._events: deque[tuple[float, bool]] = deque()
        self._lock = Lock()
        self._open = False
        self._opened_at: float | None = None
        self._reason: str | None = None
        self._on_open = None

    def set_open_callback(self, callback) -> None:
        """Register a hook fired once when the breaker trips (used for auditing)."""
        self._on_open = callback

    def record(
        self,
        *,
        error: bool,
        subject_id: str | None = None,
        policy_denial: bool = False,
    ) -> None:
        """Record an outcome and trip the breaker if thresholds are crossed.

        ``policy_denial`` marks an error that represents the firewall *working*
        (a scope escalation blocked, a revoked token refused) rather than the
        system failing. Whether these count is configurable because counting them
        lets a hostile client open the breaker on purpose -- see
        ``circuit_count_policy_denials`` in config.py.

        Exempt agents are excluded from accounting entirely so the latency
        benchmark cannot trip the breaker it is running through.
        """
        if subject_id and self._settings.is_exempt(subject_id):
            return
        if policy_denial and not self._settings.circuit_count_policy_denials:
            error = False

        now = time.time()
        window = self._settings.circuit_window_seconds
        tripped_reason: str | None = None
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
                    samples >= self._settings.circuit_min_samples
                    and rate >= self._settings.circuit_error_rate_threshold
                ):
                    tripped_reason = (
                        f"error_rate {rate:.0%} >= threshold "
                        f"{self._settings.circuit_error_rate_threshold:.0%} "
                        f"over {samples} samples in {window}s"
                    )
                elif samples > self._settings.circuit_volume_ceiling:
                    tripped_reason = (
                        f"call volume {samples} exceeded ceiling "
                        f"{self._settings.circuit_volume_ceiling} in {window}s"
                    )
                if tripped_reason:
                    self._open = True
                    self._opened_at = now
                    self._reason = tripped_reason

        if tripped_reason:
            logger.error("Circuit breaker OPEN: %s", tripped_reason)
            if self._on_open is not None:
                try:
                    self._on_open(tripped_reason)
                except Exception:  # pragma: no cover - auditing must not break the breaker
                    logger.exception("circuit-open callback failed")

    def is_open(self) -> bool:
        with self._lock:
            return self._open

    def check(self) -> None:
        """Raise :class:`CircuitOpen` if the breaker is open."""
        if self.is_open():
            raise CircuitOpen(self._reason or "circuit_open")

    def state(self) -> CircuitState:
        now = time.time()
        cutoff = now - self._settings.circuit_window_seconds
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
                volume=samples,
            )

    def reset(self) -> None:
        """Break glass: close the breaker and clear the window."""
        with self._lock:
            self._open = False
            self._opened_at = None
            self._reason = None
            self._events.clear()
        logger.warning("Circuit breaker manually reset (break glass)")


# ---------------------------------------------------------------------------
# Anomaly detection (PRD 8.7)
# ---------------------------------------------------------------------------
@dataclass
class _AgentBaseline:
    intervals: deque[float] = field(default_factory=lambda: deque(maxlen=100))
    scope_counts: deque[int] = field(default_factory=lambda: deque(maxlen=100))
    last_seen: float | None = None


class AnomalyDetector:
    """Flags unusual delegation frequency or scope diversity.

    Log-only by design (PRD 8.7): an auto-blocking anomaly detector on the
    critical path of every agent action turns a false positive into an outage.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._baselines: dict[str, _AgentBaseline] = defaultdict(_AgentBaseline)
        self._lock = Lock()

    def observe_delegation(self, subject_id: str, scope_count: int) -> str | None:
        """Record a delegation. Returns a description if it looks anomalous."""
        now = time.time()
        with self._lock:
            baseline = self._baselines[subject_id]
            interval = None if baseline.last_seen is None else now - baseline.last_seen
            baseline.last_seen = now

            findings: list[str] = []
            min_samples = self._settings.anomaly_min_baseline_samples
            sigma = self._settings.anomaly_sigma_threshold

            if interval is not None:
                if len(baseline.intervals) >= min_samples:
                    mean, std = _mean_std(baseline.intervals)
                    # A *shorter* interval than baseline means a frequency spike.
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
                        f"{mean:.2f} (std {std:.2f}) -- sigma above baseline"
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
# `x > mean + 3*0` fires on any increase, and multiplying by zero can never
# express "well outside normal". Both helpers therefore fall back to a relative
# margin when the baseline has no spread -- otherwise the most predictable agents,
# whose deviations are the most meaningful, would be the least detectable.
_ZERO_STD_RELATIVE_MARGIN = 2.0


def _is_high_outlier(value: float, mean: float, std: float, sigma: float) -> bool:
    if std > 0:
        return value > mean + sigma * std
    return value > max(mean * _ZERO_STD_RELATIVE_MARGIN, mean + 1)


def _is_low_outlier(value: float, mean: float, std: float, sigma: float) -> bool:
    if std > 0:
        return value < mean - sigma * std
    return value < mean / _ZERO_STD_RELATIVE_MARGIN
