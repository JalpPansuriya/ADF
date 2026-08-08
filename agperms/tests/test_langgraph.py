"""LangGraph guard: node-entry enforcement plus automatic checkpointing.

The decisive assertion here is that a denied node's **side effect never happens**,
not merely that an exception surfaced afterwards. Guarded nodes append to a list;
the tests assert the list is still empty.
"""

from __future__ import annotations

import pytest

from agperms import (
    ApprovalRequired,
    CompletionState,
    Config,
    Firewall,
    MemoryStorage,
    ScopeEscalationDenied,
)
from agperms.integrations.langgraph import (
    AGENT_KEY,
    DEPTH_KEY,
    SCOPES_KEY,
    TOKEN_KEY,
    AgpermsGuard,
)

SIDE_EFFECTS: list[str] = []


@pytest.fixture(autouse=True)
def _clear_side_effects():
    SIDE_EFFECTS.clear()
    yield
    SIDE_EFFECTS.clear()


@pytest.fixture
def fw() -> Firewall:
    return Firewall(
        config=Config(
            jwt_secret="test-secret-not-for-production-0123456789abcdef",
            pii_salt="test-salt",
            rate_limit_verify_per_min=100_000,
            rate_limit_action_per_min=100_000,
        ),
        storage=MemoryStorage(),
    )


@pytest.fixture
def guard(fw: Firewall) -> AgpermsGuard:
    return AgpermsGuard(fw)


@pytest.fixture
def state(fw: Firewall) -> dict:
    root = fw.mint_root(
        subject="alice",
        scopes=["read_calendar", "read_email", "web_search", "send_email"],
    )
    return {TOKEN_KEY: root.token, "task": "summarise my day"}


class TestNodeEntryGuard:
    def test_node_runs_with_sufficient_scope(self, guard: AgpermsGuard, state: dict):
        @guard.require_scope("read_calendar")
        def calendar_node(s: dict) -> dict:
            SIDE_EFFECTS.append("read_calendar")
            return {**s, "events": ["standup"]}

        result = calendar_node(state)
        assert result["events"] == ["standup"]
        assert SIDE_EFFECTS == ["read_calendar"]

    def test_denied_node_body_never_runs(self, guard: AgpermsGuard, fw: Firewall, state: dict):
        """The core guarantee."""
        narrow = guard.delegate_for_node(state, to="cal-agent", scopes=["read_calendar"])

        @guard.require_scope("web_search")
        def search_node(s: dict) -> dict:
            SIDE_EFFECTS.append("SEARCHED_THE_WEB")
            return s

        with pytest.raises(PermissionError):
            search_node(narrow)
        assert SIDE_EFFECTS == [], "side effect leaked past a denied guard"

    def test_missing_token_is_denied(self, guard: AgpermsGuard):
        @guard.require_scope("read_calendar")
        def node(s: dict) -> dict:
            SIDE_EFFECTS.append("ran")
            return s

        with pytest.raises(PermissionError):
            node({})
        assert SIDE_EFFECTS == []

    def test_revoked_capability_denies_node(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        @guard.require_scope("read_calendar")
        def node(s: dict) -> dict:
            SIDE_EFFECTS.append("ran")
            return s

        node(state)
        assert SIDE_EFFECTS == ["ran"]
        SIDE_EFFECTS.clear()

        jti = fw.verify(state[TOKEN_KEY], "read_calendar").claims.jti
        fw.revoke(jti)

        with pytest.raises(PermissionError):
            node(state)
        assert SIDE_EFFECTS == []

    def test_decorator_preserves_metadata(self, guard: AgpermsGuard):
        @guard.require_scope("read_calendar")
        def documented(s: dict) -> dict:
            """Node docstring."""
            return s

        assert documented.__name__ == "documented"
        assert documented.__doc__ == "Node docstring."
        assert documented.__agperms_scope__ == "read_calendar"
        assert documented.__agperms_checkpoint__ is True


class TestAutomaticCheckpointing:
    def test_clean_node_records_a_clean_action(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        @guard.require_scope("read_calendar")
        def calendar_node(s: dict) -> dict:
            return s

        calendar_node(state)
        completed = fw.audit_events(action="action_completed")
        assert len(completed) == 1
        assert completed[0]["detail"]["action_name"] == "calendar_node"
        assert completed[0]["detail"]["completion_state"] == "CLEAN"

    def test_raising_node_is_recorded_partial_and_reraises(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        sentinel = RuntimeError("node blew up")

        @guard.require_scope("read_calendar")
        def flaky_node(s: dict) -> dict:
            SIDE_EFFECTS.append("started")
            raise sentinel

        with pytest.raises(RuntimeError) as exc:
            flaky_node(state)
        # Unchanged: the checkpoint is a side observation, not a behaviour change.
        assert exc.value is sentinel
        assert SIDE_EFFECTS == ["started"]

        failed = fw.audit_events(action="action_failed")
        assert len(failed) == 1
        assert failed[0]["detail"]["action_name"] == "flaky_node"
        assert failed[0]["detail"]["completion_state"] == "PARTIAL"

    def test_revoke_surfaces_the_failed_node(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        @guard.require_scope("read_calendar")
        def flaky_node(s: dict) -> dict:
            raise RuntimeError("mid-flight")

        with pytest.raises(RuntimeError):
            flaky_node(state)

        jti = fw.verify(state[TOKEN_KEY], "read_calendar").claims.jti
        result = fw.revoke(jti)
        assert [r.action_name for r in result.reviews] == ["flaky_node"]
        assert result.reviews[0].classification is CompletionState.PARTIAL

    def test_checkpoint_can_be_disabled(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        @guard.require_scope("read_calendar", checkpoint=False)
        def pure_node(s: dict) -> dict:
            return s

        pure_node(state)
        assert pure_node.__agperms_checkpoint__ is False
        assert fw.audit_events(action="action_started") == []
        # Still enforced, just not checkpointed.
        assert fw.audit_events(action="verify_allowed")


class TestDelegationHook:
    def test_delegate_narrows_and_returns_new_state(
        self, guard: AgpermsGuard, state: dict
    ):
        original = dict(state)
        narrow = guard.delegate_for_node(state, to="cal-agent", scopes=["read_calendar"])
        assert narrow[SCOPES_KEY] == ["read_calendar"]
        assert narrow[AGENT_KEY] == "cal-agent"
        assert narrow[DEPTH_KEY] == 1
        assert narrow["task"] == state["task"]
        assert narrow[TOKEN_KEY] != state[TOKEN_KEY]
        # Input untouched.
        assert state == original

    def test_escalation_raises_before_dispatch(self, guard: AgpermsGuard, state: dict):
        narrow = guard.delegate_for_node(state, to="reader", scopes=["read_email"])
        with pytest.raises(ScopeEscalationDenied) as exc:
            guard.delegate_for_node(narrow, to="searcher", scopes=["web_search"])
        assert exc.value.denied_scopes == ["web_search"]
        assert SIDE_EFFECTS == []

    def test_missing_token_raises(self, guard: AgpermsGuard):
        with pytest.raises(PermissionError):
            guard.delegate_for_node({}, to="child", scopes=["read_calendar"])

    def test_sensitive_scope_surfaces_approval_required(
        self, guard: AgpermsGuard, state: dict
    ):
        with pytest.raises(ApprovalRequired) as exc:
            guard.delegate_for_node(state, to="email-agent", scopes=["send_email"])
        assert exc.value.sensitive_scopes == ["send_email"]
        # ApprovalRequired is a PermissionError, so a naive graph fails safe.
        assert isinstance(exc.value, PermissionError)

    def test_inline_approval(self, guard: AgpermsGuard, fw: Firewall, state: dict):
        approved = guard.delegate_with_approval(
            state, to="email-agent", scopes=["send_email"], approver="human:alice"
        )
        assert approved[SCOPES_KEY] == ["send_email"]
        assert fw.verify(approved[TOKEN_KEY], "send_email").valid

    def test_inline_approval_requires_an_approver(
        self, guard: AgpermsGuard, state: dict
    ):
        with pytest.raises(ApprovalRequired):
            guard.delegate_with_approval(
                state, to="email-agent", scopes=["send_email"]
            )


class TestThreeNodeGraph:
    """assistant -> calendar, assistant -> email, end to end."""

    def test_legitimate_graph_executes(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        @guard.require_scope("read_calendar")
        def calendar_node(s: dict) -> dict:
            SIDE_EFFECTS.append("calendar:read")
            return {**s, "events": ["standup", "1:1"]}

        @guard.require_scope("send_email")
        def email_node(s: dict) -> dict:
            SIDE_EFFECTS.append("email:send")
            return {**s, "sent": True}

        def assistant_node(s: dict) -> dict:
            SIDE_EFFECTS.append("assistant:plan")
            cal = calendar_node(
                guard.delegate_for_node(s, to="cal-agent", scopes=["read_calendar"])
            )
            mail = email_node(
                guard.delegate_with_approval(
                    s, to="email-agent", scopes=["send_email"], approver="human:alice"
                )
            )
            return {**mail, "events": cal["events"]}

        final = assistant_node(state)
        assert final["sent"] is True
        assert final["events"] == ["standup", "1:1"]
        assert SIDE_EFFECTS == ["assistant:plan", "calendar:read", "email:send"]

    def test_overprivileged_dispatch_aborts_with_no_side_effects(
        self, guard: AgpermsGuard, state: dict
    ):
        @guard.require_scope("web_search")
        def search_node(s: dict) -> dict:
            SIDE_EFFECTS.append("SEARCHED")
            return s

        def email_agent_node(s: dict) -> dict:
            SIDE_EFFECTS.append("email:planning")
            sub = guard.delegate_for_node(s, to="searcher", scopes=["web_search"])
            return search_node(sub)

        email_state = guard.delegate_with_approval(
            state, to="email-agent", scopes=["send_email"], approver="human:alice"
        )
        with pytest.raises(ScopeEscalationDenied) as exc:
            email_agent_node(email_state)

        assert exc.value.denied_scopes == ["web_search"]
        assert "SEARCHED" not in SIDE_EFFECTS
        assert SIDE_EFFECTS == ["email:planning"]

    def test_root_revocation_kills_the_graph(
        self, guard: AgpermsGuard, fw: Firewall, state: dict
    ):
        @guard.require_scope("read_calendar")
        def calendar_node(s: dict) -> dict:
            SIDE_EFFECTS.append("calendar:read")
            return s

        cal_state = guard.delegate_for_node(
            state, to="cal-agent", scopes=["read_calendar"]
        )
        calendar_node(cal_state)
        assert SIDE_EFFECTS == ["calendar:read"]
        SIDE_EFFECTS.clear()

        root_jti = fw.verify(state[TOKEN_KEY], "read_calendar").claims.jti
        fw.revoke(root_jti)

        with pytest.raises(PermissionError):
            calendar_node(cal_state)
        assert SIDE_EFFECTS == []
