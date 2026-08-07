"""Eval item 9: LangGraph adapter integration (PRD 16.4).

The decisive assertion is that a denied node's **side effect never happens** --
not merely that an exception was raised afterwards. A guard that runs the node and
then complains is worthless.

The adapter's ADFClient is handed FastAPI's ``TestClient`` (itself a subclass of
``httpx.Client``), so these tests exercise the real HTTP request/response contract
in-process. ``httpx.ASGITransport`` is not usable here -- it is async-only, while
``ADFClient`` is deliberately synchronous.
"""

from __future__ import annotations

import pytest

from langgraph_adf_adapter import (
    ADFClient,
    ADFDenied,
    ADFGuard,
    PendingApprovalRequired,
    TOKEN_KEY,
)
from tests.conftest import ADMIN_KEY


@pytest.fixture
def guard(client):
    """ADFGuard wired to the in-process app via the TestClient."""
    adf_client = ADFClient(
        str(client.base_url), admin_key=ADMIN_KEY, client=client
    )
    yield ADFGuard(str(client.base_url), admin_key=ADMIN_KEY, client=adf_client)


@pytest.fixture
def root_state(guard):
    root = guard.client.mint_root(
        "jalp",
        ["read_calendar", "write_calendar", "read_email", "send_email", "web_search"],
        ttl_seconds=600,
    )
    return {TOKEN_KEY: root.token, "task": "summarise my day"}


# ---------------------------------------------------------------------------
# A minimal 3-node graph. side_effects records real work performed.
# ---------------------------------------------------------------------------
side_effects: list[str] = []


@pytest.fixture(autouse=True)
def _clear_side_effects():
    side_effects.clear()
    yield
    side_effects.clear()


class TestNodeEntryGuard:
    def test_guarded_node_runs_with_sufficient_scope(self, guard, root_state):
        @guard.require_scope("read_calendar")
        def calendar_node(state: dict) -> dict:
            side_effects.append("read_calendar")
            return {**state, "events": ["standup"]}

        result = calendar_node(root_state)
        assert result["events"] == ["standup"]
        assert side_effects == ["read_calendar"]

    def test_guarded_node_blocked_without_scope_and_body_never_runs(
        self, guard, root_state
    ):
        """The core of eval item 9."""
        narrow = guard.delegate_for_node(root_state, "calendar-agent", ["read_calendar"])

        @guard.require_scope("web_search")
        def search_node(state: dict) -> dict:
            side_effects.append("PERFORMED_WEB_SEARCH")  # must never happen
            return state

        with pytest.raises(PermissionError) as exc:
            search_node(narrow)
        assert "web_search" in str(exc.value)
        assert side_effects == [], "SIDE EFFECT LEAKED past a denied guard"

    def test_missing_token_is_denied(self, guard):
        @guard.require_scope("read_calendar")
        def node(state: dict) -> dict:
            side_effects.append("ran")
            return state

        with pytest.raises(PermissionError):
            node({})
        assert side_effects == []

    def test_revoked_token_denies_node(self, guard, root_state):
        import jwt

        @guard.require_scope("read_calendar")
        def node(state: dict) -> dict:
            side_effects.append("ran")
            return state

        assert node(root_state)  # works first
        side_effects.clear()

        jti = jwt.decode(root_state[TOKEN_KEY], options={"verify_signature": False})["jti"]
        guard.client.revoke(jti, reason="test")

        with pytest.raises(PermissionError, match="revoked"):
            node(root_state)
        assert side_effects == []

    def test_decorator_preserves_metadata(self, guard):
        @guard.require_scope("read_calendar")
        def documented_node(state: dict) -> dict:
            """Node docstring."""
            return state

        assert documented_node.__name__ == "documented_node"
        assert documented_node.__doc__ == "Node docstring."
        assert documented_node.__adf_required_scope__ == "read_calendar"


class TestDelegationHook:
    def test_delegate_narrows_token_in_state(self, guard, root_state):
        new_state = guard.delegate_for_node(
            root_state, "calendar-agent", ["read_calendar"]
        )
        assert new_state[TOKEN_KEY] != root_state[TOKEN_KEY]
        assert new_state["adf_scopes"] == ["read_calendar"]
        assert new_state["adf_agent_id"] == "calendar-agent"
        assert new_state["adf_depth"] == 1
        # Unrelated state must survive the hop.
        assert new_state["task"] == root_state["task"]

    def test_original_state_not_mutated(self, guard, root_state):
        """A denial must not leave the caller's state half-rewritten."""
        original = dict(root_state)
        guard.delegate_for_node(root_state, "calendar-agent", ["read_calendar"])
        assert root_state == original

    def test_escalation_raises_before_dispatch(self, guard, root_state):
        """PRD 16.3: an over-privileged dispatch fails before the sub-graph runs."""
        narrow = guard.delegate_for_node(root_state, "email-reader", ["read_email"])

        with pytest.raises(ADFDenied) as exc:
            guard.delegate_for_node(narrow, "search-agent", ["web_search"])
        assert exc.value.denied_scopes == ["web_search"]
        assert side_effects == []

    def test_missing_token_in_state_raises(self, guard):
        with pytest.raises(ADFDenied, match="no ADF token"):
            guard.delegate_for_node({}, "child", ["read_calendar"])

    def test_sensitive_scope_surfaces_pending_approval(self, guard, root_state):
        """Must be surfaced, not silently swallowed -- the graph author decides."""
        with pytest.raises(PendingApprovalRequired) as exc:
            guard.delegate_for_node(root_state, "email-agent", ["send_email"])
        assert exc.value.approval.sensitive_scopes == ["send_email"]
        # PendingApprovalRequired is a PermissionError, so a naive graph fails safe.
        assert isinstance(exc.value, PermissionError)

    def test_delegate_with_inline_approval(self, guard, root_state):
        state = guard.delegate_with_approval(
            root_state, "email-agent", ["send_email"], approve_as_human=True
        )
        assert state["adf_scopes"] == ["send_email"]
        result = guard.client.verify(state[TOKEN_KEY], "send_email")
        assert result.valid is True


class TestThreeNodeGraph:
    """PRD 16.4: assistant -> calendar, assistant -> email, end to end."""

    def test_legitimate_graph_executes(self, guard, root_state):
        @guard.require_scope("read_calendar")
        def calendar_node(state: dict) -> dict:
            side_effects.append("calendar:read")
            return {**state, "events": ["standup", "1:1"]}

        @guard.require_scope("send_email")
        def email_node(state: dict) -> dict:
            side_effects.append("email:send")
            return {**state, "sent": True}

        def assistant_node(state: dict) -> dict:
            side_effects.append("assistant:plan")
            cal_state = guard.delegate_for_node(
                state, "calendar-agent", ["read_calendar"]
            )
            cal_result = calendar_node(cal_state)

            mail_state = guard.delegate_with_approval(
                state, "email-agent", ["send_email"], approve_as_human=True
            )
            mail_result = email_node({**mail_state, "events": cal_result["events"]})
            return mail_result

        final = assistant_node(root_state)
        assert final["sent"] is True
        assert final["events"] == ["standup", "1:1"]
        assert side_effects == ["assistant:plan", "calendar:read", "email:send"]

    def test_overprivileged_dispatch_aborts_graph_with_no_side_effects(
        self, guard, root_state
    ):
        """An email agent must not be able to spawn a web-search sub-agent."""

        @guard.require_scope("web_search")
        def search_node(state: dict) -> dict:
            side_effects.append("SEARCHED_THE_WEB")
            return state

        def email_agent_node(state: dict) -> dict:
            side_effects.append("email:planning")
            # email-agent holds only send_email; requesting web_search must fail.
            sub_state = guard.delegate_for_node(state, "search-agent", ["web_search"])
            return search_node(sub_state)

        email_state = guard.delegate_with_approval(
            root_state, "email-agent", ["send_email"], approve_as_human=True
        )

        with pytest.raises(ADFDenied) as exc:
            email_agent_node(email_state)

        assert exc.value.denied_scopes == ["web_search"]
        assert "SEARCHED_THE_WEB" not in side_effects
        assert side_effects == ["email:planning"]

    def test_root_revocation_kills_whole_graph(self, guard, root_state):
        import jwt

        @guard.require_scope("read_calendar")
        def calendar_node(state: dict) -> dict:
            side_effects.append("calendar:read")
            return state

        cal_state = guard.delegate_for_node(root_state, "calendar-agent", ["read_calendar"])
        calendar_node(cal_state)
        assert side_effects == ["calendar:read"]
        side_effects.clear()

        root_jti = jwt.decode(root_state[TOKEN_KEY], options={"verify_signature": False})[
            "jti"
        ]
        guard.client.revoke(root_jti, reason="human revoked root")

        with pytest.raises(PermissionError, match="revoked"):
            calendar_node(cal_state)
        assert side_effects == []


class TestClientErrorHandling:
    def test_denied_approval_raises_on_collect(self, guard, root_state):
        with pytest.raises(PendingApprovalRequired) as exc:
            guard.delegate_for_node(root_state, "email-agent", ["send_email"])
        approval_id = exc.value.approval.approval_id

        guard.client.deny_approval(approval_id)
        with pytest.raises(ADFDenied, match="denied"):
            guard.client.collect_approved(approval_id)

    def test_admin_operation_without_key_raises_clearly(self, client):
        no_admin = ADFClient(str(client.base_url), client=client)
        from langgraph_adf_adapter import ADFError

        with pytest.raises(ADFError, match="requires an admin key"):
            no_admin.mint_root("jalp", ["read_calendar"])

    def test_verify_of_missing_token_is_not_an_exception(self, guard):
        result = guard.client.verify(None, "read_calendar")
        assert result.valid is False
        assert result.reason == "missing_token"

    def test_health_reachable(self, guard):
        assert guard.client.health()["status"] in {"ok", "degraded"}
