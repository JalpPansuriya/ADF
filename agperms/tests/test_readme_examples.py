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
