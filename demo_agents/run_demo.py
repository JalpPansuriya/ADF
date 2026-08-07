"""Scripted end-to-end demo -- PRD Section 11, all seven steps.

Run against a live stack::

    docker compose up -d
    python demo_agents/run_demo.py

Or in-process (no server, no Docker) which is how the test suite drives it::

    python demo_agents/run_demo.py --in-process

Step 2 deviates from PRD Section 11 in one visible way: ``send_email`` is a
sensitive scope, so the Email Agent's delegation returns ``202 pending_approval``
and the script performs the human approval explicitly. The PRD said this
delegation "succeeds instantly", which contradicts PRD 8.2. Showing the gate is
strictly more informative than hiding it. See DECISIONS.md 2026-08-07.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from langgraph_adf_adapter import ADFClient, ADFDenied, DelegatedToken, PendingApproval

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_agents.agents import (  # noqa: E402
    ActionLog,
    AssistantAgent,
    CalendarAgent,
    EmailAgent,
    WebSearchAgent,
    llm_mode_enabled,
)

ROOT_SCOPES = [
    "read_calendar",
    "write_calendar",
    "read_email",
    "send_email",
    "web_search",
]


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
class Console:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.lines: list[str] = []

    def step(self, number: int, title: str) -> None:
        self._emit("")
        self._emit("=" * 78)
        self._emit(f"STEP {number}: {title}")
        self._emit("=" * 78)

    def say(self, message: str) -> None:
        self._emit(f"  {message}")

    def ok(self, message: str) -> None:
        self._emit(f"  [OK]      {message}")

    def blocked(self, message: str) -> None:
        self._emit(f"  [BLOCKED] {message}")

    def info(self, message: str) -> None:
        self._emit(f"  [info]    {message}")

    def _emit(self, message: str) -> None:
        self.lines.append(message)
        if not self.quiet:
            print(message)


@dataclass
class DemoResult:
    """Machine-checkable outcome, asserted by tests/test_demo_scenario.py."""

    root_jti: str
    calendar_jti: str
    email_jti: str
    escalation_blocked: bool
    escalation_denied_scopes: list[str]
    email_action_succeeded: bool
    revoked_subtree_count: int
    post_revocation_all_invalid: bool
    chain_jtis: list[str]
    integrity_intact: bool
    actions_performed: list[str]
    actions_blocked: list[str]
    approval_id: str | None
    console: list[str]


def run_demo(client: ADFClient, *, quiet: bool = False) -> DemoResult:
    """Execute the PRD Section 11 scenario and return a checkable result."""
    console = Console(quiet)
    actions = ActionLog()

    mode = "LLM-driven" if llm_mode_enabled() else "deterministic"
    console.say(f"Agent Delegation Firewall -- demo scenario ({mode} agents)")

    # ---------------------------------------------------------------- step 1
    console.step(1, "Human mints a root token with 5 scopes")
    root = client.mint_root("jalp", ROOT_SCOPES, ttl_seconds=1800)
    console.ok(f"root token minted: jti={root.jti}")
    console.info(f"scopes: {root.scopes}")
    console.info("note: the token's subject is an opaque UUID, never 'jalp' (PRD 8.6)")

    assistant = AssistantAgent("assistant-agent", client, actions, token=root.token)
    calendar = CalendarAgent("calendar-agent", client, actions)
    email = EmailAgent("email-agent", client, actions)
    search = WebSearchAgent("search-agent", client, actions)

    # ---------------------------------------------------------------- step 2
    console.step(2, "Assistant delegates narrower tokens to Calendar and Email agents")
    plan = assistant.plan("check my calendar and email me a summary")
    console.info(f"assistant's plan: {plan}")

    cal_result = assistant.delegate_to(calendar, ["read_calendar"])
    assert isinstance(cal_result, DelegatedToken)
    console.ok(
        f"calendar-agent received {cal_result.scopes} (depth {cal_result.depth}) "
        f"-- narrowed from 5 scopes to 1"
    )

    approval_id: str | None = None
    email_result = assistant.delegate_to(email, ["send_email"])
    if isinstance(email_result, PendingApproval):
        # This is the PRD 11 vs 8.2 contradiction, resolved in favour of 8.2.
        approval_id = email_result.approval_id
        console.blocked(
            f"email-agent delegation HELD at the approval gate: "
            f"{email_result.sensitive_scopes} requires a human"
        )
        console.info(f"approval_id={approval_id}; no token was minted")
        console.info("a human now approves (the demo satisfies the gate, never bypasses it)")
        client.approve(approval_id)
        collected = client.collect_approved(approval_id)
        assert collected is not None
        email.token = collected.token
        email_jti = collected.jti
        console.ok(f"human approved; email-agent received {collected.scopes}")
    else:
        email_jti = email_result.jti
        console.ok(f"email-agent received {email_result.scopes}")

    # ---------------------------------------------------------------- step 3
    console.step(3, "Email Agent tries to delegate web_search -- must be refused")
    escalation_blocked = False
    denied_scopes: list[str] = []
    try:
        email.delegate_to(search, ["web_search"])
        console.say("!! ESCALATION SUCCEEDED -- THE FIREWALL FAILED")
    except ADFDenied as exc:
        escalation_blocked = True
        denied_scopes = exc.denied_scopes
        console.blocked(f"403 scope_escalation_denied -- denied_scopes={denied_scopes}")
        console.info(
            "email-agent holds only ['send_email']; it cannot grant a scope it "
            "never had, even though the human's root token did have web_search"
        )

    # ---------------------------------------------------------------- step 4
    console.step(4, "Email Agent performs its legitimate action")
    agenda = calendar.read_agenda()
    console.ok(f"calendar-agent read {len(agenda)} events (verified read_calendar)")
    summary = email.send_summary(agenda)
    console.ok("email-agent sent the summary (verified send_email)")
    console.info(f"body preview: {summary.splitlines()[0]}")
    email_action_succeeded = "email:send_summary" in actions.performed

    console.say("")
    console.info("for contrast, an action outside the granted scope:")
    try:
        calendar.delete_everything()
        console.say("!! write_calendar SUCCEEDED -- THE FIREWALL FAILED")
    except ADFDenied as exc:
        console.blocked(f"calendar-agent denied write_calendar -- {exc.reason}")

    # ---------------------------------------------------------------- step 5
    console.step(5, "Human revokes the root token -- whole subtree dies instantly")
    revoke_result = client.revoke(root.jti, reason="demo: human pulled the plug")
    subtree_count = revoke_result["subtree_count"]
    console.ok(
        f"revoked {subtree_count} tokens in {revoke_result['latency_ms']:.2f}ms "
        f"(root + all descendants)"
    )

    checks = {
        "root": client.verify(root.token, "read_calendar"),
        "calendar-agent": client.verify(calendar.token, "read_calendar"),
        "email-agent": client.verify(email.token, "send_email"),
    }
    for name, result in checks.items():
        console.blocked(f"{name} now fails /verify -- reason={result.reason}")
    post_revocation_all_invalid = all(not r.valid for r in checks.values())
    console.info(
        "neither child token was touched directly; revocation propagated down the tree"
    )

    # ---------------------------------------------------------------- step 6
    console.step(6, "Full lineage for the Email Agent's token")
    chain = client.chain(email_jti)
    chain_jtis = [entry["jti"] for entry in chain["chain"]]
    for entry in chain["chain"]:
        marker = " (revoked)" if entry["revoked"] else ""
        console.say(
            f"depth {entry['depth']}: {entry['display_label'] or entry['agent_id']} "
            f"-> {entry['scopes']}{marker}"
        )
    console.info("reconstructed server-side; a caller cannot fabricate its own lineage")

    # ---------------------------------------------------------------- step 7
    console.step(7, "Audit log integrity check")
    integrity = client._get("/audit/verify_integrity")
    console.ok(
        f"intact={integrity['intact']} across {integrity['rows_checked']} "
        f"hash-chained rows"
    )
    console.info(
        "tests/test_audit_integrity.py corrupts rows directly in the database and "
        "confirms this endpoint names the first broken link"
    )

    # ---------------------------------------------------------------- summary
    console.step(8, "Summary")
    console.say(f"actions actually performed: {actions.performed}")
    console.say(f"actions blocked at the checkpoint: {actions.blocked}")
    console.say("")
    console.say("The firewall held: no agent ever exercised a capability it was not")
    console.say("explicitly granted, and revoking the human's token killed everything")
    console.say("downstream in one operation.")

    return DemoResult(
        root_jti=root.jti,
        calendar_jti=cal_result.jti,
        email_jti=email_jti,
        escalation_blocked=escalation_blocked,
        escalation_denied_scopes=denied_scopes,
        email_action_succeeded=email_action_succeeded,
        revoked_subtree_count=subtree_count,
        post_revocation_all_invalid=post_revocation_all_invalid,
        chain_jtis=chain_jtis,
        integrity_intact=bool(integrity["intact"]),
        actions_performed=list(actions.performed),
        actions_blocked=list(actions.blocked),
        approval_id=approval_id,
        console=console.lines,
    )


# ---------------------------------------------------------------------------
# Entrypoints
# ---------------------------------------------------------------------------
def _run_against_server(url: str, admin_key: str) -> DemoResult:
    with ADFClient(url, admin_key=admin_key, timeout=10.0) as client:
        try:
            client.health()
        except Exception as exc:
            raise SystemExit(
                f"Cannot reach the Checkpoint Service at {url} ({exc}).\n"
                "Start it with:  docker compose up -d\n"
                "Or run the demo without a server:  python demo_agents/run_demo.py --in-process"
            ) from exc
        return run_demo(client)


def _run_in_process() -> DemoResult:
    """Run the whole scenario in one process against SQLite + fakeredis."""
    import fakeredis
    from fastapi.testclient import TestClient

    from checkpoint_service.config import Settings
    from checkpoint_service.container import AppContainer
    from checkpoint_service.main import create_app

    settings = Settings(
        admin_api_key="in-process-demo-admin-key-0001",
        jwt_secret="in-process-demo-jwt-secret-000000000000000000",
        pii_salt="in-process-demo-salt",
        database_url="sqlite:///:memory:",
        enforce_secret_strength=False,
    )
    container = AppContainer(
        settings,
        redis_override=fakeredis.FakeRedis(decode_responses=True),
        create_tables=True,
    )
    app = create_app(container)
    with TestClient(app) as http:
        client = ADFClient(
            str(http.base_url), admin_key=settings.admin_api_key, client=http
        )
        return run_demo(client)


def main() -> int:
    parser = argparse.ArgumentParser(description="ADF demo scenario (PRD Section 11)")
    parser.add_argument(
        "--url",
        default=os.getenv("ADF_URL", "http://localhost:8000"),
        help="Checkpoint Service base URL",
    )
    parser.add_argument(
        "--admin-key",
        default=os.getenv("ADF_ADMIN_API_KEY", ""),
        help="admin key for root mint / revoke / approve",
    )
    parser.add_argument(
        "--in-process",
        action="store_true",
        help="run against an embedded instance (no server, no Docker)",
    )
    args = parser.parse_args()

    if args.in_process:
        result = _run_in_process()
    else:
        if not args.admin_key:
            raise SystemExit(
                "No admin key. Pass --admin-key or set ADF_ADMIN_API_KEY.\n"
                "Or run without a server:  python demo_agents/run_demo.py --in-process"
            )
        result = _run_against_server(args.url, args.admin_key)

    # Exit non-zero if any security-critical expectation failed, so the demo is
    # usable as a smoke test in CI rather than only as a screen recording.
    failures = []
    if not result.escalation_blocked:
        failures.append("scope escalation was NOT blocked")
    if not result.post_revocation_all_invalid:
        failures.append("tokens still valid after root revocation")
    if not result.integrity_intact:
        failures.append("audit chain integrity check failed")
    if not result.email_action_succeeded:
        failures.append("the legitimate email action did not run")
    if failures:
        print("\nDEMO FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nDemo completed: all security expectations held.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
