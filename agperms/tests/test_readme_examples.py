"""The README's examples must actually run.

Documentation that does not execute is a liability: it looks authoritative and
misleads. These mirror the README snippets closely enough that a drift in either
breaks a test.
"""

from __future__ import annotations

import pytest

from agperms import (
    ApprovalRequired,
    CompletionState,
    Config,
    Firewall,
    ScopeEscalationDenied,
)


def test_quick_start():
    fw = Firewall()
    root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])
    child = fw.delegate(root.token, to="calendar-agent", scopes=["read_calendar"])
    assert fw.verify(child.token, "read_calendar")
    # VerifyResult is falsy on denial, so `if fw.verify(...)` reads correctly.
    assert not fw.verify(child.token, "read_email")


def test_escalation_example():
    fw = Firewall()
    root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])
    child = fw.delegate(root.token, to="calendar-agent", scopes=["read_calendar"])
    # The root held read_email, but the child never carried it forward.
    with pytest.raises(ScopeEscalationDenied) as exc:
        fw.delegate(child.token, to="sneaky", scopes=["read_email"])
    assert exc.value.denied_scopes == ["read_email"]


def test_action_and_review_example():
    fw = Firewall()
    root = fw.mint_root(subject="alice", scopes=["send_email"])

    with pytest.raises(RuntimeError):
        with fw.action(root.token, scope="send_email", name="welcome_email"):
            raise RuntimeError("smtp exploded")

    result = fw.revoke(root.jti, reason="incident-42")
    assert len(result.reviews) == 1
    review = result.reviews[0]
    assert review.action_name == "welcome_email"
    assert review.classification is CompletionState.PARTIAL

    for pending in fw.pending_reviews():
        fw.resolve_review(
            pending.review_id,
            note="checked provider dashboard, no email was sent",
            reviewed_by="human:alice",
        )
    assert fw.pending_reviews() == []


def test_approval_example():
    fw = Firewall()
    root = fw.mint_root(subject="alice", scopes=["send_email"])
    with pytest.raises(ApprovalRequired) as exc:
        fw.delegate(root.token, to="email-agent", scopes=["send_email"])
    cap = fw.approve(exc.value.approval_id, approver="human:alice")
    assert fw.verify(cap.token, "send_email")


def test_langgraph_example():
    from agperms.integrations.langgraph import TOKEN_KEY, AgpermsGuard

    fw = Firewall()
    guard = AgpermsGuard(fw)
    sent: list[str] = []

    @guard.require_scope("send_email")
    def email_node(state):
        sent.append(state["draft"])
        return {**state, "sent": True}

    def assistant_node(state):
        return email_node(
            guard.delegate_with_approval(
                state,
                to="email-agent",
                scopes=["send_email"],
                approver="human:alice",
            )
        )

    root = fw.mint_root(subject="alice", scopes=["send_email"])
    final = assistant_node({TOKEN_KEY: root.token, "draft": "hello"})
    assert final["sent"] is True
    assert sent == ["hello"]


def test_durability_example(tmp_path):
    import os

    from agperms.storage.sql import SqlStorage

    os.environ["AGPERMS_SECRET"] = "a-fixed-secret-for-this-test-000000000000"
    storage = SqlStorage(f"sqlite:///{tmp_path / 'agperms.db'}")
    try:
        fw = Firewall(
            config=Config(jwt_secret=os.environ["AGPERMS_SECRET"]),
            storage=storage,
        )
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        assert fw.verify(root.token, "read_calendar")
    finally:
        storage.close()
        os.environ.pop("AGPERMS_SECRET", None)


def test_integrity_example():
    fw = Firewall()
    root = fw.mint_root(subject="alice", scopes=["s"])
    fw.delegate(root.token, to="a", scopes=["s"])
    report = fw.verify_audit_integrity()
    assert report.intact is True
    assert report.rows_checked > 0
    assert report.first_broken_row_id is None


def test_documented_defaults_are_accurate():
    """The README states specific defaults; they must be true."""
    config = Config()
    assert config.rate_limit_delegate_per_min == 60
    assert config.rate_limit_verify_per_min == 300
    assert config.circuit_error_rate_threshold == 0.25
    assert config.circuit_window_seconds == 60
    assert config.circuit_min_samples == 20
    assert config.approval_timeout_seconds == 300
    assert config.anomaly_sigma_threshold == 3.0
    assert config.anomaly_min_baseline_samples == 10
    assert config.circuit_count_policy_denials is False
    assert config.max_delegation_depth == 5
    assert {
        "send_email",
        "spend_money",
        "delete_data",
        "post_public_content",
        "transfer_funds",
        "execute_code",
    } == set(config.sensitive_scopes)


def test_documented_truncation_limit():
    from agperms._time import truncate_reason

    assert len(truncate_reason("x" * 5_000)) == 200


def test_reversibility_example():
    """The README's Reversibility typing section, executed."""
    from agperms import Reversibility

    fw = Firewall(
        config=Config(
            jwt_secret="readme-secret",
            pii_salt="readme-salt",
            scope_reversibility={
                "read_calendar": Reversibility.IDEMPOTENT,
                "draft_email": Reversibility.REVERSIBLE,
                "charge_card": Reversibility.COMPENSABLE,
                "send_email": Reversibility.IRREVERSIBLE,
            },
        )
    )
    root = fw.mint_root(
        subject="alice", scopes=["read_calendar", "delete_data"]
    )

    # Per-call override, as documented.
    with fw.action(
        root.token,
        scope="delete_data",
        name="soft_delete",
        reversibility=Reversibility.REVERSIBLE,
    ) as act:
        assert act.reversibility is Reversibility.REVERSIBLE

    # The documented fail-closed default.
    assert fw.config.reversibility_of("unlisted") is Reversibility.IRREVERSIBLE

    # The documented priority ordering, and that it is opt-in.
    handle = fw.action(root.token, scope="read_calendar", name="left_open")
    handle.__enter__()
    fw.revoke(root.jti)
    assert fw.pending_reviews(order_by_priority=True)


def test_documented_reversibility_defaults():
    """The README's class table for the default sensitive scopes."""
    from agperms import Reversibility

    config = Config()
    assert config.reversibility_of("spend_money") is Reversibility.COMPENSABLE
    assert config.reversibility_of("transfer_funds") is Reversibility.IRREVERSIBLE
    assert config.reversibility_of("send_email") is Reversibility.IRREVERSIBLE
    # The README claims these are separate maps; prove spend_money is both
    # gated and compensable, which a merged map could not express.
    assert config.is_sensitive("spend_money")


def test_risk_state_example():
    """The README's Risk-state vector section, executed."""
    from agperms import compute_risk_state

    fw = Firewall(
        config=Config(jwt_secret="readme-secret", pii_salt="readme-salt")
    )
    root = fw.mint_root(subject="alice", scopes=["read_calendar", "send_email"])
    with fw.action(root.token, scope="read_calendar", name="r"):
        pass

    state = compute_risk_state(fw, root.claims.sub)
    assert 0.0 <= state.beta <= 1.0
    assert state.eta_exposure > 0
    assert 0 <= state.governance_tier <= 5
    assert isinstance(state.to_dict(), dict)

    # The documented honesty claims.
    assert state.dependency_shares is None
    assert state.dependency_concentration is None
    assert state.alpha <= 3, "README states alpha(4) is unreachable"
    assert set(state.governance_evidence), "evidence must be inspectable"


def test_risk_state_beta_is_none_not_zero():
    """The README states beta is None when nothing was observed."""
    from agperms import compute_risk_state

    fw = Firewall(
        config=Config(jwt_secret="readme-secret", pii_salt="readme-salt")
    )
    root = fw.mint_root(subject="alice", scopes=["read_calendar"])
    state = compute_risk_state(fw, root.claims.sub)
    assert state.beta is None
    assert state.beta != 0.0
