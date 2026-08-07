"""ADFGuard -- plugs the Checkpoint Service into a LangGraph graph (PRD 16).

Two integration points:

1. :meth:`ADFGuard.require_scope` -- a node-entry guard. The decorated node only
   runs if the token in graph state carries the required scope.
2. :meth:`ADFGuard.delegate_for_node` -- called before dispatching to a sub-agent
   node; returns new state carrying a *narrowed* token, or raises on escalation.

The guard raises **before** the node body executes, which is the property that
matters: a denial must mean the side effect never happened, not that it happened
and then an error was reported.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar

from langgraph_adf_adapter.adf_client import (
    ADFClient,
    ADFDenied,
    DelegatedToken,
    PendingApproval,
)

#: Key under which the capability token travels in LangGraph state.
TOKEN_KEY = "adf_token"
AGENT_KEY = "adf_agent_id"

F = TypeVar("F", bound=Callable[..., Any])


class ADFGuard:
    """LangGraph-idiomatic wrapper around the Checkpoint Service."""

    def __init__(
        self,
        checkpoint_url: str,
        admin_key: str | None = None,
        *,
        client: ADFClient | None = None,
    ) -> None:
        self.client = client or ADFClient(checkpoint_url, admin_key)

    # ------------------------------------------------------------------
    def require_scope(self, scope: str) -> Callable[[F], F]:
        """Decorator enforcing ``scope`` before a node body runs.

        Reads the token from ``state["adf_token"]``. Raises ``PermissionError``
        (``ADFDenied``) on any failure -- expired, revoked, missing, or
        insufficient scope.
        """

        def decorator(node_fn: F) -> F:
            @wraps(node_fn)
            def wrapped(state: dict, *args, **kwargs):
                token = state.get(TOKEN_KEY)
                result = self.client.verify(token, scope)
                if not result.valid:
                    raise ADFDenied(
                        f"ADF denied node {node_fn.__name__!r}: "
                        f"scope {scope!r} -- {result.reason}",
                        payload={"required_scope": scope, "reason": result.reason},
                    )
                return node_fn(state, *args, **kwargs)

            wrapped.__adf_required_scope__ = scope  # introspection for tests/tooling
            return wrapped  # type: ignore[return-value]

        return decorator

    # ------------------------------------------------------------------
    def delegate_for_node(
        self,
        parent_state: dict,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int = 600,
    ) -> dict:
        """Narrow the token before handing state to a sub-agent node.

        Returns a **new** state dict rather than mutating the input, so a denied
        delegation cannot leave the caller's state partially rewritten. Raises
        ``ADFDenied`` on escalation.
        """
        parent_token = parent_state.get(TOKEN_KEY)
        if not parent_token:
            raise ADFDenied(
                "no ADF token in graph state; the entry node must inject one",
                payload={"missing_key": TOKEN_KEY},
            )

        result = self.client.delegate(
            parent_token, child_agent_id, requested_scopes, ttl_seconds
        )

        if isinstance(result, PendingApproval):
            # Surfaced rather than silently blocking: the graph author decides
            # whether to wait for a human, checkpoint, or abort.
            raise PendingApprovalRequired(result)

        assert isinstance(result, DelegatedToken)
        return {
            **parent_state,
            TOKEN_KEY: result.token,
            AGENT_KEY: child_agent_id,
            "adf_scopes": result.scopes,
            "adf_depth": result.depth,
        }

    def delegate_with_approval(
        self,
        parent_state: dict,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int = 600,
        *,
        approve_as_human: bool = False,
    ) -> dict:
        """Delegate, optionally satisfying the approval gate inline.

        ``approve_as_human=True`` requires the guard to hold an admin key and is
        intended for demos and tests. It **satisfies** the gate by calling the
        approve endpoint; it does not bypass it. Never enable this in a real
        deployment -- it would make the agent its own approver.
        """
        try:
            return self.delegate_for_node(
                parent_state, child_agent_id, requested_scopes, ttl_seconds
            )
        except PendingApprovalRequired as pending:
            if not approve_as_human:
                raise
            self.client.approve(pending.approval.approval_id)
            token = self.client.collect_approved(pending.approval.approval_id)
            if token is None:  # pragma: no cover - defensive
                raise ADFDenied(
                    "approval was granted but no token could be collected",
                    payload={"approval_id": pending.approval.approval_id},
                ) from pending
            return {
                **parent_state,
                TOKEN_KEY: token.token,
                AGENT_KEY: child_agent_id,
                "adf_scopes": token.scopes,
                "adf_depth": token.depth,
            }

    def close(self) -> None:
        self.client.close()


class PendingApprovalRequired(ADFDenied):
    """Raised when a delegation is parked at the human-approval gate.

    Subclasses ``ADFDenied`` (and therefore ``PermissionError``) so a graph that
    only handles denial still fails safe rather than proceeding without a token.
    """

    def __init__(self, approval: PendingApproval) -> None:
        super().__init__(
            f"human approval required for scopes {approval.sensitive_scopes}",
            status_code=202,
            payload={
                "approval_id": approval.approval_id,
                "sensitive_scopes": approval.sensitive_scopes,
            },
        )
        self.approval = approval
