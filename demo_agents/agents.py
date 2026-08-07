"""Toy agents that exercise the Checkpoint Service.

Deterministic by default: decisions are scripted, so the demo and the test that
runs it are reproducible and require no API key. Set ``ADF_LLM_MODE=1`` (plus a
provider key) to let a model choose which scopes to request -- useful for showing
that the firewall constrains a *real* model's choices, but not something a test
should depend on.

The agents deliberately hold no privilege of their own: every capability arrives
as a token, and every action is gated by ``/tokens/verify``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from langgraph_adf_adapter import (
    ADFClient,
    ADFDenied,
    DelegatedToken,
    PendingApproval,
)

logger = logging.getLogger(__name__)


def llm_mode_enabled() -> bool:
    return os.getenv("ADF_LLM_MODE", "").strip() in {"1", "true", "yes"}


@dataclass
class ActionLog:
    """Record of real work performed, used to prove denials had no side effects."""

    performed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)

    def did(self, what: str) -> None:
        self.performed.append(what)

    def was_blocked(self, what: str) -> None:
        self.blocked.append(what)


class BaseAgent:
    """Common behaviour: hold a token, verify before acting, delegate downward."""

    #: Scopes this agent needs to do its own job.
    required_scopes: tuple[str, ...] = ()

    def __init__(
        self,
        agent_id: str,
        client: ADFClient,
        actions: ActionLog,
        token: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.client = client
        self.actions = actions
        self.token = token

    # ------------------------------------------------------------------
    def guard(self, scope: str) -> None:
        """Enforcement checkpoint. Raises before any work happens."""
        result = self.client.verify(self.token, scope)
        if not result.valid:
            self.actions.was_blocked(f"{self.agent_id}:{scope}")
            raise ADFDenied(
                f"{self.agent_id} denied scope {scope!r}: {result.reason}",
                payload={"required_scope": scope, "reason": result.reason},
            )

    def delegate_to(
        self,
        child: "BaseAgent",
        scopes: list[str],
        ttl_seconds: int = 600,
    ) -> DelegatedToken | PendingApproval:
        """Request a narrowed token for a sub-agent.

        Never copies its own token downward -- that is precisely the failure mode
        ADF exists to prevent.
        """
        assert self.token, f"{self.agent_id} has no token to delegate from"
        result = self.client.delegate(self.token, child.agent_id, scopes, ttl_seconds)
        if isinstance(result, DelegatedToken):
            child.token = result.token
        return result


class CalendarAgent(BaseAgent):
    required_scopes = ("read_calendar",)

    def read_agenda(self) -> list[str]:
        self.guard("read_calendar")
        self.actions.did("calendar:read_agenda")
        return ["09:30 standup", "14:00 1:1 with Priya", "16:00 design review"]

    def delete_everything(self) -> None:
        """Deliberately over-reaching action, used to show the checkpoint biting."""
        self.guard("write_calendar")
        self.actions.did("calendar:delete_everything")


class EmailAgent(BaseAgent):
    required_scopes = ("send_email",)

    def send_summary(self, agenda: list[str]) -> str:
        self.guard("send_email")
        body = "Today's agenda:\n" + "\n".join(f"  - {item}" for item in agenda)
        self.actions.did("email:send_summary")
        return body

    def read_inbox(self) -> list[str]:
        self.guard("read_email")
        self.actions.did("email:read_inbox")
        return ["Re: design review"]


class WebSearchAgent(BaseAgent):
    required_scopes = ("web_search",)

    def search(self, query: str) -> list[str]:
        self.guard("web_search")
        self.actions.did(f"web:search:{query}")
        return [f"result for {query}"]


class AssistantAgent(BaseAgent):
    """Top-level agent holding the human's root token."""

    def plan(self, task: str) -> list[tuple[str, list[str]]]:
        """Decide which sub-agents to spawn and with which scopes.

        Deterministic by default. In LLM mode a model proposes the plan -- and the
        firewall constrains it identically, which is the interesting part: a
        hallucinated over-broad request is refused rather than honoured.
        """
        if llm_mode_enabled():
            plan = self._llm_plan(task)
            if plan:
                return plan
        return [
            ("calendar-agent", ["read_calendar"]),
            ("email-agent", ["send_email"]),
        ]

    def _llm_plan(self, task: str) -> list[tuple[str, list[str]]] | None:
        """Ask a model for a delegation plan. Returns None if unavailable."""
        try:
            import json

            from openai import OpenAI  # imported lazily; optional dependency
        except Exception:
            logger.warning("ADF_LLM_MODE set but the openai package is unavailable")
            return None
        if not os.getenv("OPENAI_API_KEY"):
            logger.warning("ADF_LLM_MODE set but OPENAI_API_KEY is missing")
            return None
        try:
            response = OpenAI().chat.completions.create(
                model=os.getenv("ADF_LLM_MODEL", "gpt-4o-mini"),
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Return JSON: {\"plan\":[{\"agent\":str,\"scopes\":[str]}]}. "
                            "Valid agents: calendar-agent, email-agent, search-agent. "
                            "Valid scopes: read_calendar, write_calendar, read_email, "
                            "send_email, web_search. Grant the least privilege needed."
                        ),
                    },
                    {"role": "user", "content": task},
                ],
                response_format={"type": "json_object"},
            )
            payload = json.loads(response.choices[0].message.content or "{}")
            return [(item["agent"], item["scopes"]) for item in payload.get("plan", [])]
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning("LLM planning failed (%s); using the scripted plan", exc)
            return None
