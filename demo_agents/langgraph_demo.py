"""The same scenario expressed as a real LangGraph graph (PRD 16.3).

Demonstrates that ADF is framework-agnostic: the enforcement is identical, just
wrapped in LangGraph idioms. If ``langgraph`` is not installed the module falls
back to driving the node functions directly -- the guard logic under test is the
same either way, since ``ADFGuard`` only ever sees a state dict.

    python demo_agents/langgraph_demo.py --in-process
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langgraph_adf_adapter import (  # noqa: E402
    ADFDenied,
    ADFGuard,
    TOKEN_KEY,
)

ROOT_SCOPES = ["read_calendar", "write_calendar", "read_email", "send_email", "web_search"]

# Real work performed, so a denial can be shown to have produced no side effect.
SIDE_EFFECTS: list[str] = []


def build_nodes(guard: ADFGuard):
    """Create the three guarded nodes plus the assistant that delegates to them."""

    @guard.require_scope("read_calendar")
    def calendar_node(state: dict) -> dict:
        SIDE_EFFECTS.append("calendar:read")
        return {**state, "events": ["09:30 standup", "14:00 1:1", "16:00 design review"]}

    @guard.require_scope("send_email")
    def email_node(state: dict) -> dict:
        SIDE_EFFECTS.append("email:send")
        return {**state, "sent": True}

    @guard.require_scope("web_search")
    def search_node(state: dict) -> dict:
        # Reached only if the firewall fails; its presence in SIDE_EFFECTS is
        # the failure signal.
        SIDE_EFFECTS.append("web:search")
        return {**state, "results": ["..."]}

    def assistant_node(state: dict) -> dict:
        SIDE_EFFECTS.append("assistant:plan")
        cal_state = guard.delegate_for_node(state, "calendar-agent", ["read_calendar"])
        cal_out = calendar_node(cal_state)

        mail_state = guard.delegate_with_approval(
            state, "email-agent", ["send_email"], approve_as_human=True
        )
        mail_out = email_node({**mail_state, "events": cal_out["events"]})
        return {**mail_out, "events": cal_out["events"]}

    return assistant_node, calendar_node, email_node, search_node


def run(guard: ADFGuard) -> dict:
    SIDE_EFFECTS.clear()
    print("LangGraph + ADF demo")
    print("=" * 60)

    root = guard.client.mint_root("jalp", ROOT_SCOPES, ttl_seconds=900)
    state = {TOKEN_KEY: root.token, "task": "summarise my day and email it"}
    print(f"root token minted (5 scopes), jti={root.jti}")

    assistant_node, calendar_node, email_node, search_node = build_nodes(guard)

    graph_used = "direct function calls"
    try:
        from langgraph.graph import END, StateGraph

        graph = StateGraph(dict)
        graph.add_node("assistant", assistant_node)
        graph.set_entry_point("assistant")
        graph.add_edge("assistant", END)
        compiled = graph.compile()
        final = compiled.invoke(state)
        graph_used = "compiled LangGraph StateGraph"
    except ImportError:
        print("(langgraph not installed -- driving the nodes directly)")
        final = assistant_node(state)

    print(f"executed via: {graph_used}")
    print(f"legitimate flow completed: sent={final.get('sent')}, "
          f"events={len(final.get('events', []))}")
    print(f"side effects: {SIDE_EFFECTS}")

    print("\nnow the over-privileged dispatch:")
    email_state = guard.delegate_with_approval(
        {TOKEN_KEY: root.token}, "email-agent", ["send_email"], approve_as_human=True
    )
    before = list(SIDE_EFFECTS)
    try:
        sub_state = guard.delegate_for_node(email_state, "search-agent", ["web_search"])
        search_node(sub_state)
        print("  !! ESCALATION SUCCEEDED -- THE FIREWALL FAILED")
        escalation_blocked = False
    except ADFDenied as exc:
        escalation_blocked = True
        print(f"  [BLOCKED] PermissionError before the node ran: {exc}")
        print(f"  denied_scopes={exc.denied_scopes}")

    leaked = [effect for effect in SIDE_EFFECTS if effect not in before]
    print(f"  new side effects after the denial: {leaked or 'none'}")

    return {
        "escalation_blocked": escalation_blocked,
        "side_effects": list(SIDE_EFFECTS),
        "web_search_leaked": "web:search" in SIDE_EFFECTS,
        "graph_used": graph_used,
    }


def _in_process_guard():
    import fakeredis
    from fastapi.testclient import TestClient

    from checkpoint_service.config import Settings
    from checkpoint_service.container import AppContainer
    from checkpoint_service.main import create_app
    from langgraph_adf_adapter import ADFClient

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
    http = TestClient(create_app(container))
    http.__enter__()
    client = ADFClient(str(http.base_url), admin_key=settings.admin_api_key, client=http)
    return ADFGuard(str(http.base_url), admin_key=settings.admin_api_key, client=client), http


def main() -> int:
    parser = argparse.ArgumentParser(description="LangGraph + ADF demo (PRD 16.3)")
    parser.add_argument("--url", default=os.getenv("ADF_URL", "http://localhost:8000"))
    parser.add_argument("--admin-key", default=os.getenv("ADF_ADMIN_API_KEY", ""))
    parser.add_argument("--in-process", action="store_true")
    args = parser.parse_args()

    if args.in_process:
        guard, http = _in_process_guard()
        try:
            result = run(guard)
        finally:
            http.__exit__(None, None, None)
    else:
        if not args.admin_key:
            raise SystemExit(
                "No admin key. Pass --admin-key / set ADF_ADMIN_API_KEY, or use --in-process."
            )
        guard = ADFGuard(args.url, admin_key=args.admin_key)
        try:
            result = run(guard)
        finally:
            guard.close()

    if not result["escalation_blocked"] or result["web_search_leaked"]:
        print("\nDEMO FAILED: the firewall did not hold")
        return 1
    print("\nDemo completed: escalation blocked with no leaked side effects.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
