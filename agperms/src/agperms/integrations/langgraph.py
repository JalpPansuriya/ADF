"""LangGraph integration.

Two integration points, mirroring the HTTP adapter that ships with the
Checkpoint Service:

1. :meth:`AgpermsGuard.require_scope` -- a node-entry guard. The decorated node
   only runs if the capability in graph state carries the scope, and the node body
   is automatically wrapped in an action checkpoint so a revoke can tell you what
   the node was in the middle of.
2. :meth:`AgpermsGuard.delegate_for_node` -- narrows the capability before handing
   state to a sub-agent.

The guard raises *before* the node body executes. That ordering is the whole
point: a denial must mean the side effect never happened, not that it happened and
an error was reported afterwards.

LangGraph itself is not imported here. The guard only ever sees a state dict, so
it works on any callable with that shape -- which also means it is testable
without the framework installed.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar

from agperms.errors import ApprovalRequired, Denied
from agperms.firewall import Firewall
from agperms.models import Capability

#: Key under which the capability travels in LangGraph state.
TOKEN_KEY = "agperms_token"
AGENT_KEY = "agperms_agent_id"
SCOPES_KEY = "agperms_scopes"
DEPTH_KEY = "agperms_depth"

F = TypeVar("F", bound=Callable[..., Any])


class AgpermsGuard:
    """Wraps a :class:`~agperms.Firewall` in LangGraph idioms."""

    def __init__(self, firewall: Firewall) -> None:
        self.firewall = firewall

    # ------------------------------------------------------------------
    def require_scope(
        self, scope: str, *, checkpoint: bool = True
    ) -> Callable[[F], F]:
        """Enforce ``scope`` before a node body runs, and checkpoint the body.

        The capability is read from ``state[TOKEN_KEY]``. On any failure --
        missing, expired, revoked, insufficient scope -- this raises
        :class:`~agperms.errors.Denied` (a ``PermissionError``) before the node
        executes.

        With ``checkpoint=True`` (the default) the node body runs inside an action
        checkpoint named after the node function, so if the capability is revoked
        while the node is mid-flight, the revoke reports PARTIAL/UNKNOWN rather
        than silently having no idea. Any exception the node raises is re-raised
        unchanged -- the checkpoint is a side observation, never a behaviour change.

        Pass ``checkpoint=False`` for nodes that are pure computation with no side
        effects worth reviewing.
        """

        def decorator(node_fn: F) -> F:
            @wraps(node_fn)
            def wrapped(state: dict, *args: Any, **kwargs: Any):
                token = state.get(TOKEN_KEY)
                if not checkpoint:
                    self.firewall.require(token, scope)
                    return node_fn(state, *args, **kwargs)
                # `action` verifies the capability on entry and raises before the
                # body runs, so there is no separate check to make here.
                with self.firewall.action(
                    token or "", scope=scope, name=node_fn.__name__
                ):
                    return node_fn(state, *args, **kwargs)

            wrapped.__agperms_scope__ = scope  # type: ignore[attr-defined]
            wrapped.__agperms_checkpoint__ = checkpoint  # type: ignore[attr-defined]
            return wrapped  # type: ignore[return-value]

        return decorator

    # ------------------------------------------------------------------
    def delegate_for_node(
        self,
        state: dict,
        *,
        to: str,
        scopes: list[str],
        ttl_seconds: int | None = None,
    ) -> dict:
        """Narrow the capability before dispatching to a sub-agent node.

        Returns a **new** state dict rather than mutating the input, so a refused
        delegation cannot leave the caller's state half-rewritten. Raises
        :class:`~agperms.errors.ScopeEscalationDenied` on escalation and
        :class:`~agperms.errors.ApprovalRequired` when a human is needed -- the
        latter is surfaced rather than swallowed so the graph author decides
        whether to wait, checkpoint, or abort.
        """
        token = state.get(TOKEN_KEY)
        if not token:
            raise Denied("missing_token", missing_key=TOKEN_KEY)

        child = self.firewall.delegate(
            token, to=to, scopes=scopes, ttl_seconds=ttl_seconds
        )
        return self._state_with(state, child, to)

    def delegate_with_approval(
        self,
        state: dict,
        *,
        to: str,
        scopes: list[str],
        ttl_seconds: int | None = None,
        approver: str | None = None,
    ) -> dict:
        """Delegate, satisfying the approval gate inline when ``approver`` is set.

        This **satisfies** the gate, it does not bypass it: an approval is recorded
        against ``approver``. Intended for demos, tests, and flows where the human
        is genuinely present. Passing an ``approver`` that is really the agent
        itself would make the agent its own approver -- don't.
        """
        try:
            return self.delegate_for_node(
                state, to=to, scopes=scopes, ttl_seconds=ttl_seconds
            )
        except ApprovalRequired as pending:
            if approver is None:
                raise
            self.firewall.approve(pending.approval_id, approver=approver)
            child = self.firewall.collect(pending.approval_id)
            if child is None:  # pragma: no cover - defensive
                raise Denied(
                    "approval_granted_but_uncollectable",
                    approval_id=pending.approval_id,
                ) from pending
            return self._state_with(state, child, to)

    # ------------------------------------------------------------------
    @staticmethod
    def _state_with(state: dict, child: Capability, agent_id: str) -> dict:
        return {
            **state,
            TOKEN_KEY: child.token,
            AGENT_KEY: agent_id,
            SCOPES_KEY: list(child.scopes),
            DEPTH_KEY: child.depth,
        }


__all__ = [
    "AGENT_KEY",
    "AgpermsGuard",
    "DEPTH_KEY",
    "SCOPES_KEY",
    "TOKEN_KEY",
]
