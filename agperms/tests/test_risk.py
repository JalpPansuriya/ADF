"""Risk-state vector: (alpha, beta, eta, g, v).

From *AI-Native Insurance for Agentic AI* (Zhu, arXiv:2607.13230). These tests
pin the arithmetic, and -- more importantly -- pin the honesty: the components
agperms cannot observe must stay absent rather than be invented, and an
unmeasurable beta must be None rather than a flattering zero.
"""

from __future__ import annotations

import pytest

from agperms import (
    Config,
    Firewall,
    MemoryStorage,
    Reversibility,
    compute_risk_state,
)
from agperms.risk import (
    PERMISSION_WEIGHTS,
    autonomy_category,
    governance_tier,
    herfindahl,
    permission_class_of,
    permission_exposure,
)


class TestPermissionExposure:
    def test_unknown_scope_is_treated_as_state_changing(self):
        """Fail closed: an unclassified scope is not assumed to be a read."""
        assert permission_class_of("brand_new_scope") == "record_modification"

    def test_known_scopes_map_to_their_class(self):
        assert permission_class_of("send_email") == "email"
        assert permission_class_of("transfer_funds") == "payments"
        assert permission_class_of("read_calendar") == "read"

    def test_overrides_win(self):
        assert (
            permission_class_of("send_email", overrides={"send_email": "payments"})
            == "payments"
        )

    def test_exposure_counts_classes_not_scopes(self):
        """Three email scopes are one email permission, not three."""
        _, one = permission_exposure(["send_email"])
        classes, three = permission_exposure(
            ["send_email", "post_public_content"]
        )
        # Both map to "email".
        assert classes == frozenset({"email"})
        assert one == three

    def test_exposure_is_weighted_by_class(self):
        _, email = permission_exposure(["send_email"])
        _, payments = permission_exposure(["transfer_funds"])
        assert payments > email
        assert email == PERMISSION_WEIGHTS["email"]
        assert payments == PERMISSION_WEIGHTS["payments"]

    def test_empty_scopes_have_no_exposure(self):
        classes, exposure = permission_exposure([])
        assert classes == frozenset()
        assert exposure == 0.0

    def test_custom_weights_are_honoured(self):
        _, exposure = permission_exposure(
            ["send_email"], weights={"email": 99.0}
        )
        assert exposure == 99.0


class TestAutonomyCategory:
    def test_no_scopes_is_assistive(self):
        assert autonomy_category(depth=0, worst=None, delegates_further=False) == 0

    def test_idempotent_only_is_assistive(self):
        assert (
            autonomy_category(
                depth=0, worst=Reversibility.IDEMPOTENT, delegates_further=False
            )
            == 0
        )

    def test_reversible_is_copilot(self):
        assert (
            autonomy_category(
                depth=0, worst=Reversibility.REVERSIBLE, delegates_further=False
            )
            == 1
        )

    def test_irreversible_leaf_is_digital_agent(self):
        assert (
            autonomy_category(
                depth=1, worst=Reversibility.IRREVERSIBLE, delegates_further=False
            )
            == 2
        )

    def test_delegating_onward_is_multi_agent(self):
        assert (
            autonomy_category(
                depth=1, worst=Reversibility.IRREVERSIBLE, delegates_further=True
            )
            == 3
        )

    def test_cyber_physical_is_never_inferred(self):
        """A scope name cannot tell us it drives a robot; 4 stays unreachable."""
        worst_possible = autonomy_category(
            depth=99, worst=Reversibility.IRREVERSIBLE, delegates_further=True
        )
        assert worst_possible == 3


class TestHerfindahl:
    def test_single_provider_is_total_concentration(self):
        assert herfindahl({"openai": 1.0}) == pytest.approx(1.0)

    def test_even_split_across_four_is_one_quarter(self):
        shares = {"a": 0.25, "b": 0.25, "c": 0.25, "d": 0.25}
        assert herfindahl(shares) == pytest.approx(0.25)

    def test_unnormalised_input_is_normalised(self):
        """A caller passing raw counts should still get a meaningful answer."""
        assert herfindahl({"a": 50, "b": 50}) == pytest.approx(0.5)

    def test_empty_or_zero_is_zero(self):
        assert herfindahl({}) == 0.0
        assert herfindahl({"a": 0.0}) == 0.0


class TestGovernanceTier:
    def test_default_firewall_scores_low(self):
        """Ephemeral key + in-memory storage is not a governed deployment."""
        fw = Firewall()
        tier, evidence = governance_tier(fw)
        assert evidence["durable_storage"] is False
        assert evidence["persistent_signing_key"] is False
        assert evidence["audit_chain_intact"] is True
        assert tier == 3  # chain intact, queue clear, gate configured

    def test_supplied_secret_is_recognised(self, config: Config):
        fw = Firewall(config=config, storage=MemoryStorage())
        _, evidence = governance_tier(fw)
        assert evidence["persistent_signing_key"] is True

    def test_unresolved_reviews_lower_the_tier(self, fw: Firewall, root):
        before, _ = governance_tier(fw)
        handle = fw.action(root.token, scope="read_calendar", name="left_open")
        handle.__enter__()
        fw.revoke(root.jti)
        after, evidence = governance_tier(fw)
        assert evidence["review_queue_clear"] is False
        assert after == before - 1

    def test_evidence_is_returned_not_just_a_number(self):
        """A bare tier is unauditable; the checks behind it must be visible."""
        _, evidence = governance_tier(Firewall())
        assert set(evidence) == {
            "durable_storage",
            "persistent_signing_key",
            "audit_chain_intact",
            "review_queue_clear",
            "approval_gate_configured",
        }


class TestComputeRiskState:
    def test_beta_is_none_when_nothing_observed(self, fw: Firewall, root):
        """0/0 is unknown, not 'fully governed'."""
        state = compute_risk_state(fw, root.claims.sub)
        assert state.beta is None
        assert state.beta_is_measured is False
        assert state.actions_observed == 0

    def test_beta_counts_unapproved_actions_as_autonomous(self, fw: Firewall, root):
        for _ in range(3):
            with fw.action(root.token, scope="read_calendar", name="r"):
                pass
        state = compute_risk_state(fw, root.claims.sub)
        # A root minted without the approval gate is autonomous by definition.
        assert state.actions_observed == 3
        assert state.actions_autonomous == 3
        assert state.beta == pytest.approx(1.0)

    def test_scopes_come_from_durable_metadata(self, fw: Firewall, root):
        state = compute_risk_state(fw, root.claims.sub)
        assert "read" in state.eta
        assert state.eta_exposure > 0

    def test_dependency_stays_none_when_not_supplied(self, fw: Firewall, root):
        """agperms cannot observe a vendor mix, so it must not invent one."""
        state = compute_risk_state(fw, root.claims.sub)
        assert state.dependency_shares is None
        assert state.dependency_concentration is None

    def test_caller_supplied_dependencies_are_used(self, fw: Firewall, root):
        state = compute_risk_state(
            fw, root.claims.sub, dependency_shares={"openai": 0.9, "anthropic": 0.1}
        )
        assert state.dependency_concentration == pytest.approx(0.82)

    def test_worst_reversibility_is_reported(self, config: Config):
        cfg = config.with_overrides(
            scope_reversibility={"read_calendar": Reversibility.IDEMPOTENT}
        )
        fw = Firewall(config=cfg, storage=MemoryStorage())
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        state = compute_risk_state(fw, root.claims.sub)
        assert state.worst_reversibility is Reversibility.IDEMPOTENT
        assert state.alpha == 0

    def test_unclassified_scope_drives_alpha_up(self, fw: Firewall, root):
        """Default scopes are unclassified, so they read as IRREVERSIBLE."""
        state = compute_risk_state(fw, root.claims.sub)
        assert state.worst_reversibility is Reversibility.IRREVERSIBLE
        assert state.alpha >= 2

    def test_delegation_raises_alpha_to_multi_agent(self, fw: Firewall, root):
        fw.delegate(root.token, to="sub-agent", scopes=["read_calendar"])
        state = compute_risk_state(fw, root.claims.sub)
        assert state.alpha == 3

    def test_to_dict_is_flat_and_serialisable(self, fw: Firewall, root):
        state = compute_risk_state(fw, root.claims.sub)
        as_dict = state.to_dict()
        assert as_dict["subject_id"] == root.claims.sub
        assert isinstance(as_dict["eta"], list)  # sorted, not a set
        assert as_dict["dependency_shares"] is None

    def test_reads_nothing_it_cannot_verify(self, fw: Firewall, root):
        """An unknown subject yields an empty profile, not an error or a guess."""
        state = compute_risk_state(fw, "agent:does-not-exist")
        assert state.eta == frozenset()
        assert state.beta is None
        assert state.worst_reversibility is None
        assert state.alpha == 0
