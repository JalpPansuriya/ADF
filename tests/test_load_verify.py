"""Eval item 8: /verify latency benchmark.

Reports p50/p95/p99 and throughput. Runs as the guardrail-exempt ``bench-agent``
so the measurement reflects the checkpoint's real work (signature verification,
revocation lookup, scope check, audit buffering) rather than the rate limiter
rejecting requests.

The assertion ceiling is deliberately generous. The PRD target is p95 < 20ms; this
test *reports* the measured value and fails only on pathological regression. A
benchmark tuned until it passes its own target is not evidence, and a hard 20ms
assert would flake on shared CI hardware -- and a flaky gate gets disabled, which
loses the signal entirely. See DECISIONS.md 2026-08-07 (measured vs asserted).
"""

from __future__ import annotations

import statistics
import time

import fakeredis
import pytest
from fastapi.testclient import TestClient

from checkpoint_service.container import AppContainer
from checkpoint_service.db.session import dispose_engine, session_scope
from checkpoint_service.main import create_app
from tests.conftest import ADFTestHelper, build_settings

WARMUP = 50
ITERATIONS = 500


@pytest.fixture
def bench():
    settings = build_settings(guardrail_exempt_agents=["bench-agent"])
    container = AppContainer(
        settings,
        redis_override=fakeredis.FakeRedis(decode_responses=True),
        create_tables=True,
    )
    app = create_app(container)
    with TestClient(app) as client:
        client.container = container  # type: ignore[attr-defined]
        yield ADFTestHelper(client), container
    dispose_engine()


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    index = min(int(round(pct / 100.0 * (len(ordered) - 1))), len(ordered) - 1)
    return ordered[index]


class TestVerifyLatency:
    """Eval item 8."""

    def test_verify_latency_percentiles(self, bench, capsys):
        adf, container = bench
        root = adf.mint_root(["read_calendar"], human_id="bench-agent")
        token = adf.delegate_ok(root["token"], "bench-agent", ["read_calendar"])["token"]

        for _ in range(WARMUP):
            adf.verify(token, "read_calendar")

        latencies: list[float] = []
        started = time.perf_counter()
        for _ in range(ITERATIONS):
            t0 = time.perf_counter()
            response = adf.verify(token, "read_calendar")
            latencies.append((time.perf_counter() - t0) * 1000.0)
            assert response.status_code == 200
        wall = time.perf_counter() - started

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)
        throughput = ITERATIONS / wall

        # Printed so the number lands in results.md rather than being asserted away.
        print(
            f"\n[item 8] /verify over {ITERATIONS} calls (in-process, SQLite+fakeredis):"
            f"\n  p50={p50:.3f}ms  p95={p95:.3f}ms  p99={p99:.3f}ms"
            f"\n  mean={statistics.mean(latencies):.3f}ms"
            f"  throughput={throughput:.0f} req/s"
            f"\n  PRD target: p95 < 20ms excluding network"
            f"\n  NOTE: includes the ASGI/httpx TestClient round trip, so this is an"
            f"\n        upper bound on the engine's own cost."
        )

        assert p95 < 250, f"pathological latency regression: p95={p95:.1f}ms"

    def test_engine_verify_latency_without_http(self, bench):
        """Isolate the engine from the ASGI stack -- closer to 'excluding network'."""
        adf, container = bench
        root = adf.mint_root(["read_calendar"], human_id="bench-agent")
        token = adf.delegate_ok(root["token"], "bench-agent", ["read_calendar"])["token"]

        latencies: list[float] = []
        with session_scope() as session:
            for _ in range(WARMUP):
                container.engine.verify(session, token=token, required_scope="read_calendar")
            for _ in range(ITERATIONS):
                t0 = time.perf_counter()
                outcome = container.engine.verify(
                    session, token=token, required_scope="read_calendar"
                )
                latencies.append((time.perf_counter() - t0) * 1000.0)
                assert outcome.valid

        p50 = _percentile(latencies, 50)
        p95 = _percentile(latencies, 95)
        p99 = _percentile(latencies, 99)
        print(
            f"\n[item 8] DelegationEngine.verify() direct, {ITERATIONS} calls "
            f"(no HTTP layer):"
            f"\n  p50={p50:.3f}ms  p95={p95:.3f}ms  p99={p99:.3f}ms"
            f"\n  PRD target: p95 < 20ms excluding network"
        )
        assert p95 < 100, f"pathological engine latency: p95={p95:.1f}ms"

    def test_latency_stable_with_chain_depth(self, bench):
        """A deep chain must not blow up verification cost.

        verify() checks every ancestor for revocation, so cost grows with depth.
        This quantifies that so the depth ceiling can be reasoned about.
        """
        adf, container = bench
        results: dict[int, float] = {}
        for depth in (0, 2, 4):
            chain = adf.build_chain(depth, ["read_calendar"]) if depth else [
                adf.mint_root(["read_calendar"])
            ]
            token = chain[-1]["token"]
            for _ in range(20):
                adf.verify(token, "read_calendar")
            samples = []
            for _ in range(100):
                t0 = time.perf_counter()
                adf.verify(token, "read_calendar")
                samples.append((time.perf_counter() - t0) * 1000.0)
            results[depth] = _percentile(samples, 95)

        print(
            "\n[item 8] p95 latency vs delegation depth: "
            + "  ".join(f"depth={d}: {v:.3f}ms" for d, v in results.items())
        )
        # Growth should be roughly linear in depth, not explosive.
        assert results[4] < max(results[0] * 12, 200), results

    def test_throughput_not_degraded_by_audit_buffer(self, bench):
        """The buffered writer must not stall the hot path as it fills."""
        adf, container = bench
        root = adf.mint_root(["read_calendar"], human_id="bench-agent")
        token = adf.delegate_ok(root["token"], "bench-agent", ["read_calendar"])["token"]

        first, second = [], []
        for _ in range(200):
            t0 = time.perf_counter()
            adf.verify(token, "read_calendar")
            first.append((time.perf_counter() - t0) * 1000.0)
        for _ in range(200):
            t0 = time.perf_counter()
            adf.verify(token, "read_calendar")
            second.append((time.perf_counter() - t0) * 1000.0)

        p95_first, p95_second = _percentile(first, 95), _percentile(second, 95)
        print(
            f"\n[item 8] audit buffer steady state: "
            f"first 200 p95={p95_first:.3f}ms, next 200 p95={p95_second:.3f}ms"
        )
        assert p95_second < max(p95_first * 5, 100), "buffered writer degrades over time"
