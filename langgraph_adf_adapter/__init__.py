"""LangGraph adapter for the Agent Delegation Firewall.

Usage::

    from langgraph_adf_adapter import ADFGuard

    adf = ADFGuard(checkpoint_url="http://localhost:8000")

    @adf.require_scope("send_email")
    def email_node(state):
        ...   # only runs if state["adf_token"] carries send_email
"""

from langgraph_adf_adapter.adf_client import (
    ADFClient,
    ADFDenied,
    ADFError,
    DelegatedToken,
    PendingApproval,
    VerifyResult,
)
from langgraph_adf_adapter.guard import (
    AGENT_KEY,
    TOKEN_KEY,
    ADFGuard,
    PendingApprovalRequired,
)

__version__ = "1.0.0"

__all__ = [
    "ADFClient",
    "ADFDenied",
    "ADFError",
    "ADFGuard",
    "AGENT_KEY",
    "DelegatedToken",
    "PendingApproval",
    "PendingApprovalRequired",
    "TOKEN_KEY",
    "VerifyResult",
]
