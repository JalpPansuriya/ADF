"""F11: the scripted demo scenario must actually hold, not merely print nicely.

Runs the PRD Section 11 script in-process and asserts every security-critical
outcome. This is the Layer-3 (system-level) check from HARNESS_ENGINEERING Part 6:
all components together, side effects confirmed.
"""

from __future__ import annotations

import pytest

from demo_agents.run_demo import ROOT_SCOPES, run_demo
from langgraph_adf_adapter import ADFClient
from tests.conftest import ADMIN_KEY


@pytest.fixture
def demo_result(client):
    adf_client = ADFClient(str(client.base_url), admin_key=ADMIN_KEY, client=client)
    return run_demo(adf_client, quiet=True)


class TestDemoScenario:
    def test_escalation_was_blocked(self, demo_result):
        assert demo_result.escalation_blocked is True
        assert demo_result.escalation_denied_scopes == ["web_search"]

    def test_legitimate_actions_ran(self, demo_result):
        assert "calendar:read_agenda" in demo_result.actions_performed
        assert "email:send_summary" in demo_result.actions_performed
        assert demo_result.email_action_succeeded is True

    def test_out_of_scope_action_never_ran(self, demo_result):
        """The denied action must be absent from performed work, not just logged."""
        assert "calendar:delete_everything" not in demo_result.actions_performed
        assert "calendar-agent:write_calendar" in demo_result.actions_blocked

    def test_web_search_never_happened(self, demo_result):
        assert not any(a.startswith("web:") for a in demo_result.actions_performed)

    def test_approval_gate_was_exercised_not_bypassed(self, demo_result):
        """PRD 11 vs 8.2: the demo must satisfy the gate, not skip it."""
        assert demo_result.approval_id is not None

    def test_revocation_killed_the_subtree(self, demo_result):
        assert demo_result.revoked_subtree_count == 3
        assert demo_result.post_revocation_all_invalid is True

    def test_chain_lineage_reaches_the_root(self, demo_result):
        assert demo_result.chain_jtis[0] == demo_result.root_jti
        assert demo_result.chain_jtis[-1] == demo_result.email_jti

    def test_audit_chain_intact_after_full_run(self, demo_result):
        assert demo_result.integrity_intact is True

    def test_all_seven_steps_were_narrated(self, demo_result):
        output = "\n".join(demo_result.console)
        for step in range(1, 8):
            assert f"STEP {step}:" in output

    def test_no_raw_human_id_in_tokens(self, client):
        """The demo mints for human 'jalp'; the name must not reach a token."""
        response = client.post(
            "/api/v1/tokens/root",
            json={"human_id": "jalp", "scopes": ROOT_SCOPES, "ttl_seconds": 600},
            headers={"X-Admin-Key": ADMIN_KEY},
        )
        assert "jalp" not in response.json()["token"]


class TestDemoIsUsableAsSmokeTest:
    def test_in_process_entrypoint_exits_zero(self):
        """`run_demo.py --in-process` must be runnable as a CI smoke test."""
        from demo_agents.run_demo import _run_in_process

        result = _run_in_process()
        assert result.escalation_blocked
        assert result.post_revocation_all_invalid
        assert result.integrity_intact
