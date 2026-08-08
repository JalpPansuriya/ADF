"""Rate limiting, circuit breaking and anomaly flagging."""

from __future__ import annotations

import pytest

from agperms import (
    CircuitOpen,
    Config,
    Firewall,
    MemoryStorage,
    RateLimitExceeded,
    ScopeEscalationDenied,
)
from agperms._guardrails import AnomalyDetector, CircuitBreaker, LocalWindowCache, RateLimiter


def _fw(**overrides) -> Firewall:
    base = dict(
        jwt_secret="test-secret-not-for-production-0123456789abcdef",
        pii_salt="test-salt",
    )
    base.update(overrides)
    return Firewall(config=Config(**base), storage=MemoryStorage())


class TestRateLimiting:
    def test_verify_budget_is_enforced(self):
        fw = _fw(rate_limit_verify_per_min=5)
        root = fw.mint_root(subject="alice", scopes=["s"])
        allowed = 0
        with pytest.raises(RateLimitExceeded):
            for _ in range(20):
                fw.verify(root.token, "s")
                allowed += 1
        assert allowed == 5

    def test_delegate_budget_is_enforced(self):
        fw = _fw(rate_limit_delegate_per_min=3)
        root = fw.mint_root(subject="alice", scopes=["s"])
        with pytest.raises(RateLimitExceeded):
            for i in range(10):
                fw.delegate(root.token, to=f"a{i}", scopes=["s"])

    def test_limits_are_per_subject(self):
        fw = _fw(rate_limit_verify_per_min=3)
        a = fw.mint_root(subject="alice", scopes=["s"])
        b = fw.mint_root(subject="bob", scopes=["s"])
        for _ in range(3):
            fw.verify(a.token, "s")
        with pytest.raises(RateLimitExceeded):
            fw.verify(a.token, "s")
        # bob is untouched by alice's exhaustion
        assert fw.verify(b.token, "s").valid

    def test_forged_token_cannot_spend_a_real_budget(self):
        fw = _fw(rate_limit_verify_per_min=3)
        root = fw.mint_root(subject="alice", scopes=["s"])
        for _ in range(50):
            fw.verify("garbage", "s")  # fails signature before the limiter
        assert fw.verify(root.token, "s").valid

    def test_exempt_agent_is_not_limited(self):
        fw = _fw(rate_limit_verify_per_min=2, exempt_agents=frozenset({"bench"}))
        root = fw.mint_root(subject="bench", scopes=["s"])
        for _ in range(30):
            assert fw.verify(root.token, "s").valid

    def test_exemption_matches_opaque_subject(self):
        """The allowlist holds raw names, but tokens carry opaque uuids."""
        config = Config(
            jwt_secret="test-secret-not-for-production-0123456789abcdef",
            pii_salt="test-salt",
            exempt_agents=frozenset({"bench"}),
        )
        fw = Firewall(config=config, storage=MemoryStorage())
        root = fw.mint_root(subject="bench", scopes=["s"])
        assert root.claims.sub.startswith("human:")
        assert root.claims.sub != "bench"
        assert config.is_exempt(root.claims.sub) is True

    def test_snapshot_and_reset(self):
        limiter = RateLimiter(Config(jwt_secret="x" * 40, pii_salt="y"), LocalWindowCache())
        limiter.check("agent:1", "verify")
        assert limiter.snapshot()["verify:agent:1"] == 1
        limiter.reset()
        assert limiter.snapshot() == {}


class TestCircuitBreaker:
    def test_policy_denials_do_not_trip_by_default(self):
        """A blocked escalation is the firewall working, not the system failing.

        Counting these would let any client open the breaker for everyone else
        just by spamming requests that get correctly refused.
        """
        fw = _fw(circuit_min_samples=5)
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        for _ in range(30):
            with pytest.raises(ScopeEscalationDenied):
                fw.delegate(root.token, to="greedy", scopes=["web_search"])
        assert fw.circuit_state().open is False
        # And a legitimate call still works.
        assert fw.verify(root.token, "read_calendar").valid

    def test_policy_denials_trip_when_configured(self):
        fw = _fw(circuit_min_samples=5, circuit_count_policy_denials=True)
        for _ in range(10):
            fw.verify("garbage", "s")
        assert fw.circuit_state().open is True

    def test_open_breaker_refuses_valid_tokens(self):
        fw = _fw(circuit_min_samples=5, circuit_count_policy_denials=True)
        root = fw.mint_root(subject="alice", scopes=["s"])
        assert fw.verify(root.token, "s").valid
        for _ in range(10):
            fw.verify("garbage", "s")
        outcome = fw.verify(root.token, "s")
        assert not outcome.valid and outcome.reason == "circuit_open"

    def test_open_breaker_blocks_delegation(self):
        fw = _fw(circuit_min_samples=5, circuit_count_policy_denials=True)
        root = fw.mint_root(subject="alice", scopes=["s"])
        for _ in range(10):
            fw.verify("garbage", "s")
        with pytest.raises(CircuitOpen):
            fw.delegate(root.token, to="child", scopes=["s"])

    def test_below_min_samples_does_not_trip(self):
        """One early failure must not take the service down."""
        fw = _fw(circuit_min_samples=20, circuit_count_policy_denials=True)
        for _ in range(3):
            fw.verify("garbage", "s")
        assert fw.circuit_state().open is False

    def test_no_automatic_recovery(self):
        fw = _fw(circuit_min_samples=5, circuit_count_policy_denials=True)
        for _ in range(10):
            fw.verify("garbage", "s")
        for _ in range(50):
            fw.verify("garbage", "s")
        assert fw.circuit_state().open is True

    def test_break_glass_reset(self):
        fw = _fw(circuit_min_samples=5, circuit_count_policy_denials=True)
        root = fw.mint_root(subject="alice", scopes=["s"])
        for _ in range(10):
            fw.verify("garbage", "s")
        assert fw.circuit_state().open is True
        fw.reset_circuit()
        assert fw.circuit_state().open is False
        assert fw.verify(root.token, "s").valid
        assert len(fw.audit_events(action="circuit_reset")) == 1

    def test_trip_is_audited(self):
        fw = _fw(circuit_min_samples=5, circuit_count_policy_denials=True)
        for _ in range(10):
            fw.verify("garbage", "s")
        rows = fw.audit_events(action="circuit_opened")
        assert len(rows) == 1
        assert "error_rate" in rows[0]["reason"]


class TestAnomalyDetector:
    def _config(self) -> Config:
        return Config(jwt_secret="x" * 40, pii_salt="y", anomaly_min_baseline_samples=10)

    def test_zero_variance_baseline_still_detects_a_spike(self):
        """A perfectly stable agent must not become undetectable.

        `x > mean + 3*0` fires on any increase and no multiple of zero expresses
        "well outside normal", so a std of 0 needs a relative fallback -- otherwise
        the most predictable agents, whose deviations carry the most signal, would
        be the least detectable.
        """
        detector = AnomalyDetector(self._config())
        for _ in range(15):
            assert detector.observe_delegation("agent:x", 1) is None
        finding = detector.observe_delegation("agent:x", 25)
        assert finding is not None
        assert "25 scopes" in finding

    def test_no_finding_before_a_baseline_exists(self):
        detector = AnomalyDetector(self._config())
        assert detector.observe_delegation("agent:new", 50) is None

    def test_anomaly_flags_but_never_blocks(self):
        """A false positive must not become an outage."""
        fw = _fw(anomaly_min_baseline_samples=3)
        root = fw.mint_root(subject="alice", scopes=["a", "b", "c", "d", "e"])
        for i in range(6):
            fw.delegate(root.token, to=f"agent{i}", scopes=["a"])
        # A sudden wide request: flagged if detected, but always allowed through.
        child = fw.delegate(root.token, to="wide", scopes=["a", "b", "c", "d", "e"])
        assert child.scopes == ("a", "b", "c", "d", "e")
        for row in fw.audit_events(action="anomaly_flagged"):
            assert row["decision"] == "flag"
            assert row["detail"]["auto_blocked"] is False

    def test_reset_clears_baselines(self):
        detector = AnomalyDetector(self._config())
        for _ in range(15):
            detector.observe_delegation("agent:x", 1)
        detector.reset()
        assert detector.observe_delegation("agent:x", 99) is None


class TestConfigValidation:
    def test_generated_secret_when_unset(self):
        a, b = Config(), Config()
        assert a.jwt_secret and b.jwt_secret
        assert a.jwt_secret != b.jwt_secret  # per-instance, not a shared constant

    def test_rejects_bad_error_rate(self):
        from agperms import ConfigurationError

        for bad in (0.0, -0.1, 1.5):
            with pytest.raises(ConfigurationError):
                Config(circuit_error_rate_threshold=bad)

    def test_rejects_non_hmac_algorithm(self):
        from agperms import ConfigurationError

        with pytest.raises(ConfigurationError, match="HMAC"):
            Config(jwt_algorithm="RS256")

    def test_rejects_zero_depth(self):
        from agperms import ConfigurationError

        with pytest.raises(ConfigurationError):
            Config(max_delegation_depth=0)

    def test_sensitive_scope_helpers(self):
        config = Config(sensitive_scopes=frozenset({"send_email"}))
        assert config.is_sensitive("send_email")
        assert not config.is_sensitive("read_calendar")
        assert config.sensitive_subset(["read_calendar", "send_email"]) == ["send_email"]

    def test_with_overrides_returns_a_copy(self):
        base = Config(max_delegation_depth=3)
        wider = base.with_overrides(max_delegation_depth=7)
        assert base.max_delegation_depth == 3
        assert wider.max_delegation_depth == 7
