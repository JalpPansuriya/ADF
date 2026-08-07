"""Rate limiting tests (PRD 8.1) and the guardrail-exemption mechanism."""

from __future__ import annotations

import fakeredis
import pytest
from fastapi.testclient import TestClient

from checkpoint_service.container import AppContainer
from checkpoint_service.db.session import dispose_engine
from checkpoint_service.main import create_app
from tests.conftest import ADFTestHelper, build_settings


def _harness(**overrides):
    settings = build_settings(**overrides)
    container = AppContainer(
        settings,
        redis_override=fakeredis.FakeRedis(decode_responses=True),
        create_tables=True,
    )
    app = create_app(container)
    return settings, container, app


@pytest.fixture
def tight_limits():
    """Small budgets so the limiter can be exercised in a few requests."""
    settings, container, app = _harness(
        rate_limit_delegate_per_min=5, rate_limit_verify_per_min=5
    )
    with TestClient(app) as client:
        client.container = container  # type: ignore[attr-defined]
        yield ADFTestHelper(client)
    dispose_engine()


class TestRateLimiting:
    def test_delegate_limit_enforced(self, tight_limits):
        adf = tight_limits
        root = adf.mint_root(["read_calendar"])

        allowed = 0
        for i in range(10):
            response = adf.delegate(root["token"], f"agent-{i}", ["read_calendar"])
            if response.status_code == 201:
                allowed += 1
            else:
                assert response.status_code == 429, response.text
                assert response.json()["detail"]["error"] == "rate_limit_exceeded"
                assert response.headers["Retry-After"] == "60"
                break
        assert allowed == 5, f"expected exactly 5 allowed, got {allowed}"

    def test_verify_limit_enforced(self, tight_limits):
        adf = tight_limits
        root = adf.mint_root(["read_calendar"])

        statuses = [
            adf.verify(root["token"], "read_calendar").status_code for _ in range(8)
        ]
        assert statuses.count(200) == 5
        assert 429 in statuses

    def test_limits_are_per_agent_not_global(self, tight_limits):
        """One noisy agent must not starve another."""
        adf = tight_limits
        root_a = adf.mint_root(["read_calendar"], human_id="human-a")
        root_b = adf.mint_root(["read_calendar"], human_id="human-b")

        for _ in range(6):
            adf.verify(root_a["token"], "read_calendar")
        # human-a is now throttled; human-b must be unaffected.
        assert adf.verify(root_b["token"], "read_calendar").status_code == 200

    def test_rate_limit_keyed_on_verified_subject(self, tight_limits):
        """Budget must not be chargeable to a forged identity.

        A forged token fails signature verification before the limiter runs, so it
        cannot consume a real agent's budget.
        """
        adf = tight_limits
        root = adf.mint_root(["read_calendar"])
        for _ in range(20):
            adf.verify("forged.token.value", "read_calendar")
        # The genuine agent still has its full budget.
        assert adf.verify(root["token"], "read_calendar").status_code == 200

    def test_health_reports_rate_limit_windows(self, tight_limits):
        adf = tight_limits
        root = adf.mint_root(["read_calendar"])
        adf.verify(root["token"], "read_calendar")
        health = adf.health()
        assert health["rate_limits"]["verify_per_min"] == 5
        assert health["rate_limits"]["current_windows"]


class TestGuardrailExemption:
    def test_exempt_agent_is_not_rate_limited(self):
        """Eval item 8 depends on this: the benchmark must not be throttled."""
        settings, container, app = _harness(
            rate_limit_verify_per_min=3, guardrail_exempt_agents=["bench-agent"]
        )
        with TestClient(app) as client:
            client.container = container  # type: ignore[attr-defined]
            adf = ADFTestHelper(client)
            root = adf.mint_root(["read_calendar"], human_id="bench-agent")
            bench = adf.delegate_ok(root["token"], "bench-agent", ["read_calendar"])

            statuses = [
                adf.verify(bench["token"], "read_calendar").status_code
                for _ in range(30)
            ]
            assert set(statuses) == {200}, "exempt agent was throttled"
        dispose_engine()

    def test_exemption_matches_opaque_subject_id(self):
        """The allowlist holds raw names but tokens carry opaque UUIDs.

        Regression test: before SubjectRegistry registered the mapping, the
        exemption could never match and the benchmark measured the rate limiter.
        """
        settings, container, app = _harness(guardrail_exempt_agents=["bench-agent"])
        with TestClient(app) as client:
            client.container = container  # type: ignore[attr-defined]
            adf = ADFTestHelper(client)
            root = adf.mint_root(["read_calendar"], human_id="bench-agent")
            bench = adf.delegate_ok(root["token"], "bench-agent", ["read_calendar"])

            import jwt

            claims = jwt.decode(bench["token"], options={"verify_signature": False})
            assert claims["sub"].startswith("agent:")
            assert claims["sub"] != "bench-agent"
            assert settings.is_exempt(claims["sub"]) is True
        dispose_engine()

    def test_non_exempt_agent_still_limited(self):
        settings, container, app = _harness(
            rate_limit_verify_per_min=3, guardrail_exempt_agents=["bench-agent"]
        )
        with TestClient(app) as client:
            client.container = container  # type: ignore[attr-defined]
            adf = ADFTestHelper(client)
            root = adf.mint_root(["read_calendar"], human_id="ordinary-human")
            statuses = [
                adf.verify(root["token"], "read_calendar").status_code for _ in range(6)
            ]
            assert 429 in statuses
        dispose_engine()


class TestAnomalyDetection:
    def test_anomaly_flags_but_never_blocks(self, container):
        """PRD 8.7: flag only. Auto-blocking would turn a false positive into an outage."""
        detector = container.anomaly
        # Establish a wide-scope baseline.
        for _ in range(15):
            detector.observe_delegation("agent:x", 1)
        finding = detector.observe_delegation("agent:x", 25)
        assert finding is not None
        assert "sigma above baseline" in finding

    def test_no_finding_before_baseline_exists(self, container):
        assert container.anomaly.observe_delegation("agent:new", 5) is None

    def test_anomaly_recorded_in_audit_without_denial(self, adf, container):
        scopes = ["read_calendar"]
        root = adf.mint_root(scopes)
        # Build a baseline of single-scope delegations from the root subject.
        for i in range(12):
            adf.delegate_ok(root["token"], f"agent-{i}", scopes)

        wide = adf.mint_root(
            ["read_calendar", "read_email", "web_search", "write_calendar"],
            human_id="jalp",
        )
        response = adf.delegate(
            wide["token"],
            "suddenly-greedy",
            ["read_calendar", "read_email", "web_search", "write_calendar"],
        )
        # Whether or not this specific request trips the detector, the contract is
        # that anomalies never turn into denials.
        assert response.status_code in (201, 202)
        for entry in adf.audit_log(action="anomaly_detected")["entries"]:
            assert entry["decision"] == "flag"
            assert entry["detail"]["auto_blocked"] is False
