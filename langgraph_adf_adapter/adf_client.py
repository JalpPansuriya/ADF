"""Thin HTTP client for the Checkpoint Service.

Kept deliberately dependency-light (httpx only) so it can be embedded in any
agent runtime. It exposes exactly the four operations an agent needs -- verify,
delegate, collect an approved token, and read a chain -- and nothing
administrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


class ADFError(RuntimeError):
    """Transport or protocol failure talking to the Checkpoint Service."""


class ADFDenied(PermissionError):
    """The Checkpoint Service refused the operation.

    Subclasses ``PermissionError`` so LangGraph nodes can catch either this or
    the built-in type, matching the interface in PRD 16.2.
    """

    def __init__(
        self,
        reason: str,
        *,
        status_code: int | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code
        self.payload = payload or {}

    @property
    def denied_scopes(self) -> list[str]:
        return list(self.payload.get("denied_scopes", []))


@dataclass
class VerifyResult:
    valid: bool
    reason: str | None = None
    agent_id: str | None = None
    jti: str | None = None
    remaining_scopes: list[str] = field(default_factory=list)
    depth: int | None = None


@dataclass
class DelegatedToken:
    token: str
    jti: str
    scopes: list[str]
    depth: int
    expires_at: str
    approval_required: bool = False
    approved_by: str | None = None


@dataclass
class PendingApproval:
    approval_id: str
    requested_scopes: list[str]
    sensitive_scopes: list[str]
    message: str
    expires_at: str


class ADFClient:
    """Synchronous client for the Checkpoint Service REST API."""

    def __init__(
        self,
        checkpoint_url: str,
        admin_key: str | None = None,
        *,
        timeout: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = checkpoint_url.rstrip("/")
        self.api = f"{self.base_url}/api/v1"
        self._admin_key = admin_key
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> ADFClient:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def verify(self, token: str | None, required_scope: str) -> VerifyResult:
        """Check a token against a required scope.

        A missing token is reported as an invalid result rather than raising, so
        node guards can treat "no credential" and "bad credential" uniformly.
        """
        if not token:
            return VerifyResult(valid=False, reason="missing_token")
        data = self._post("/tokens/verify", json={"token": token, "required_scope": required_scope})
        if not data.get("valid"):
            return VerifyResult(valid=False, reason=data.get("reason", "denied"))
        return VerifyResult(
            valid=True,
            agent_id=data.get("agent_id"),
            jti=data.get("jti"),
            remaining_scopes=list(data.get("remaining_scopes", [])),
            depth=data.get("depth"),
        )

    def delegate(
        self,
        parent_token: str,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int = 600,
    ) -> DelegatedToken | PendingApproval:
        """Request a narrowed child token.

        Raises :class:`ADFDenied` on scope escalation. Returns
        :class:`PendingApproval` when the request needs a human, which callers
        must handle -- it is not an error.
        """
        response = self._client.post(
            f"{self.api}/tokens/delegate",
            json={
                "child_agent_id": child_agent_id,
                "requested_scopes": requested_scopes,
                "ttl_seconds": ttl_seconds,
            },
            headers={"Authorization": f"Bearer {parent_token}"},
        )
        if response.status_code == 202:
            body = response.json()
            return PendingApproval(
                approval_id=body["approval_id"],
                requested_scopes=list(body.get("requested_scopes", [])),
                sensitive_scopes=list(body.get("sensitive_scopes", [])),
                message=body.get("message", "pending approval"),
                expires_at=body.get("expires_at", ""),
            )
        if response.status_code == 201:
            body = response.json()
            return DelegatedToken(
                token=body["token"],
                jti=body["jti"],
                scopes=list(body["scopes"]),
                depth=body["depth"],
                expires_at=body["expires_at"],
                approval_required=body.get("approval_required", False),
                approved_by=body.get("approved_by"),
            )
        self._raise_for_denial(response)

    def collect_approved(self, approval_id: str) -> DelegatedToken | None:
        """Poll for a token released by human approval. ``None`` while pending."""
        data = self._get(f"/tokens/pending/{approval_id}")
        if data.get("status") != "approved" or not data.get("token"):
            if data.get("status") in {"denied", "expired"}:
                raise ADFDenied(
                    f"delegation {data['status']}: {data.get('message', '')}",
                    payload=data,
                )
            return None
        return DelegatedToken(
            token=data["token"],
            jti=data["jti"],
            scopes=list(data.get("scopes", [])),
            depth=data.get("depth", -1),
            expires_at=data.get("expires_at") or "",
            approval_required=True,
        )

    def chain(self, jti: str) -> dict[str, Any]:
        """Full delegation lineage for a token."""
        return self._get(f"/audit/chain/{jti}")

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    # ------------------------------------------------------------------
    # Admin operations (only usable when an admin key was supplied)
    # ------------------------------------------------------------------
    def mint_root(
        self,
        human_id: str,
        scopes: list[str],
        ttl_seconds: int = 3600,
        max_depth: int | None = None,
    ) -> DelegatedToken:
        body: dict[str, Any] = {
            "human_id": human_id,
            "scopes": scopes,
            "ttl_seconds": ttl_seconds,
        }
        if max_depth is not None:
            body["max_depth"] = max_depth
        data = self._post("/tokens/root", json=body, admin=True)
        return DelegatedToken(
            token=data["token"],
            jti=data["jti"],
            scopes=list(data["scopes"]),
            depth=0,
            expires_at=data["expires_at"],
        )

    def approve(self, approval_id: str) -> dict[str, Any]:
        return self._post(
            "/tokens/approve",
            json={"approval_id": approval_id, "decision": "approve"},
            admin=True,
        )

    def deny_approval(self, approval_id: str) -> dict[str, Any]:
        return self._post(
            "/tokens/deny",
            json={"approval_id": approval_id, "decision": "deny"},
            admin=True,
        )

    def revoke(self, jti: str, reason: str | None = None) -> dict[str, Any]:
        return self._post(
            "/tokens/revoke", json={"jti": jti, "reason": reason}, admin=True
        )

    # ------------------------------------------------------------------
    def _headers(self, admin: bool) -> dict[str, str]:
        if not admin:
            return {}
        if not self._admin_key:
            raise ADFError(
                "this operation requires an admin key; construct ADFClient with admin_key="
            )
        return {"X-Admin-Key": self._admin_key}

    def _post(self, path: str, *, json: dict, admin: bool = False) -> dict[str, Any]:
        try:
            response = self._client.post(
                f"{self.api}{path}", json=json, headers=self._headers(admin)
            )
        except httpx.HTTPError as exc:
            raise ADFError(f"checkpoint service unreachable: {exc}") from exc
        if response.status_code >= 400 and path != "/tokens/verify":
            self._raise_for_denial(response)
        return response.json()

    def _get(self, path: str, *, admin: bool = False) -> dict[str, Any]:
        try:
            response = self._client.get(f"{self.api}{path}", headers=self._headers(admin))
        except httpx.HTTPError as exc:
            raise ADFError(f"checkpoint service unreachable: {exc}") from exc
        if response.status_code >= 400:
            self._raise_for_denial(response)
        return response.json()

    @staticmethod
    def _raise_for_denial(response: httpx.Response):
        try:
            body = response.json()
        except Exception:  # pragma: no cover - non-JSON error body
            raise ADFError(f"HTTP {response.status_code}: {response.text[:200]}") from None
        detail = body.get("detail", body) if isinstance(body, dict) else body
        if isinstance(detail, dict):
            reason = detail.get("error") or detail.get("reason") or str(detail)
            raise ADFDenied(str(reason), status_code=response.status_code, payload=detail)
        raise ADFDenied(str(detail), status_code=response.status_code, payload={})
