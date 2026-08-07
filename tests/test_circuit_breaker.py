"""Eval item 5: the circuit breaker trips correctly.

These tests use ``circuit_count_policy_denials=True`` (the PRD 8.3 default) to
exercise the breaker via denied requests. The rest of the suite disables that so
the escalation matrix does not trip it -- see DECISIONS.md 2026-08-07 and the
note in conftest.
"""

from __future__ import annotations

import fakeredis
import pytest
from fastapi.testclient import TestClient

from checkpoint_service.container import AppContainer
from checkpoint_service.db.session import dispose_engine
from checkpoint_service.main import create_app
from tests.conftest import ADMIN_KEY, ADFTestHelper, build_settings


@pytest.fixture
def breaker_adf():
    """Container whose breaker counts policy denials and trips after 10 samples."""
    settings = build_settings(
        circuit_count_policy_denials=True,
        circuit_min_samples=10,
        circuit_error_rate_threshold=0.25,
        rate_limit_verify_per_min=100_000,
        rate_limit_delegate_per_min=100_000,
    )
    container = AppContainer(
        settings, redis_override=fakeredis.FakeRedis(decode_responses=True), create_tables=True
    )
    app = create_app(container)
    with TestClient(app) as client:
        client.container = container  # type: ignore[attr-defined]
        yield ADFTestHelper(client)
    dispose_engine()


class TestCircuitBreakerTrips:
    """Eval item 5."""

    def test_error_spike_opens_breaker_within_one_window(self, breaker_adf):
        adf = breaker_adf
        assert adf.health()["circuit"]["open"] is False

        # Synthetically spike the error rate with forged tokens.
        for _ in range(12):
            adf.verify("not-a-real-jwt", "read_calendar")

        health = adf.health()
        assert health["circuit"]["open"] is True, health
        assert health["circuit"]["error_rate"] >= 0.25
        assert health["status"] == "degraded"

    def test_verify_returns_circuit_open_while_tripped(self, breaker_adf):
        adf = breaker_adf
        root = adf.mint_root(["read_calendar"])
        assert adf.verify(root["token"], "read_calendar").json()["valid"] is True

        for _ in range(12):
            adf.verify("garbage-token", "read_calendar")

        # A perfectly valid token is now refused: the breaker is fail-closed.
        result = adf.verify(root["token"], "read_calendar")
        assert result.status_code == 401
        assert result.json()["reason"] == "circuit_open"

    def test_delegate_blocked_while_tripped(self, breaker_adf):
        adf = breaker_adf
        root = adf.mint_root(["read_calendar"])
        for _ in range(12):
            adf.verify("garbage-token", "read_calendar")

        response = adf.delegate(root["token"], "child-agent", ["read_calendar"])
        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "circuit_open"

    def test_below_min_samples_does_not_trip(self, breaker_adf):
        """A tiny sample of errors must not open the breaker.

        Without a minimum, a single early failure would be a 100% error rate and
        take the service down on its first bad request.
        """
        adf = breaker_adf
        for _ in range(3):
            adf.verify("garbage-token", "read_calendar")
        assert adf.health()["circuit"]["open"] is False

    def test_low_error_rate_does_not_trip(self, breaker_adf):
        adf = breaker_adf
        root = adf.mint_root(["read_calendar"])
        for _ in range(30):
            adf.verify(root["token"], "read_calendar")
        adf.verify("garbage-token", "read_calendar")  # ~3% error rate
        health = adf.health()
        assert health["circuit"]["open"] is False
        assert health["circuit"]["error_rate"] < 0.25

    def test_breaker_trip_is_audited(self, breaker_adf):
        adf = breaker_adf
        for _ in range(12):
            adf.verify("garbage-token", "read_calendar")
        entries = adf.audit_log(action="circuit_opened")["entries"]
        assert len(entries) >= 1
        assert "error_rate" in entries[0]["reason"]


class TestBreakGlassReset:
    def test_admin_can_reset_breaker(self, breaker_adf):
        adf = breaker_adf
        root = adf.mint_root(["read_calendar"])
        for _ in range(12):
            adf.verify("garbage-token", "read_calendar")
        assert adf.health()["circuit"]["open"] is True

        response = adf.client.post(
            "/api/v1/admin/circuit/reset", headers={"X-Admin-Key": ADMIN_KEY}
        )
        assert response.status_code == 200
        assert response.json()["was_open"] is True

        assert adf.health()["circuit"]["open"] is False
        assert adf.verify(root["token"], "read_calendar").json()["valid"] is True

    def test_reset_requires_admin_key(self, breaker_adf):
        response = breaker_adf.client.post("/api/v1/admin/circuit/reset")
        assert response.status_code == 401

    def test_reset_is_audited(self, breaker_adf):
        adf = breaker_adf
        for _ in range(12):
            adf.verify("garbage-token", "read_calendar")
        adf.client.post(
            "/api/v1/admin/circuit/reset", headers={"X-Admin-Key": ADMIN_KEY}
        )
        entries = adf.audit_log(action="circuit_reset")["entries"]
        assert len(entries) == 1
        assert entries[0]["actor_id"] == "human:admin"

    def test_no_automatic_recovery(self, breaker_adf):
        """The breaker must stay open until a human intervenes (PRD 8.3).

        Auto-recovery would hide the incident and allow flapping while the
        underlying fault persists.
        """
        adf = breaker_adf
        for _ in range(12):
            adf.verify("garbage-token", "read_calendar")
        for _ in range(20):
            adf.verify("garbage-token", "read_calendar")
        assert adf.health()["circuit"]["open"] is True


class TestExemptAgentsBypassBreaker:
    def test_exempt_agent_errors_do_not_trip_breaker(self):
        """The benchmark identity must not be able to open the breaker."""
        settings = build_settings(
            circuit_count_policy_denials=True,
            circuit_min_samples=5,
            guardrail_exempt_agents=["bench-agent"],
            rate_limit_verify_per_min=100_000,
        )
        container = AppContainer(
            settings,
            redis_override=fakeredis.FakeRedis(decode_responses=True),
            create_tables=True,
        )
        app = create_app(container)
        with TestClient(app) as client:
            client.container = container  # type: ignore[attr-defined]
            adf = ADFTestHelper(client)
            root = adf.mint_root(["read_calendar"], human_id="bench-agent")
            bench = adf.delegate_ok(root["token"], "bench-agent", ["read_calendar"])

            # Exempt subject repeatedly asks for a scope it lacks.
            for _ in range(20):
                adf.verify(bench["token"], "web_search")

            assert adf.health()["circuit"]["open"] is False
        dispose_engine()
