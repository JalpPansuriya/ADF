"""F07: API contract tests.

Asserts the documented PRD Section 6 request/response shapes field-by-field. A
consumer integrating against the PRD must not be surprised by the implementation.
"""

from __future__ import annotations

import pytest


class TestRootEndpoint:
    def test_201_response_shape(self, adf):
        body = adf.mint_root(["read_calendar"])
        assert set(body) >= {"token", "jti", "expires_at"}
        assert isinstance(body["token"], str) and body["token"].count(".") == 2
        assert body["scopes"] == ["read_calendar"]
        assert body["max_depth"] == 5

    def test_max_depth_defaults_to_config(self, adf):
        assert adf.mint_root(["read_calendar"])["max_depth"] == 5

    def test_max_depth_override_honoured(self, adf):
        assert adf.mint_root(["read_calendar"], max_depth=3)["max_depth"] == 3

    @pytest.mark.parametrize(
        "payload",
        [
            {"human_id": "jalp", "scopes": [], "ttl_seconds": 60},
            {"human_id": "", "scopes": ["a"], "ttl_seconds": 60},
            {"human_id": "jalp", "scopes": ["a"], "ttl_seconds": 0},
            {"human_id": "jalp", "scopes": ["a"], "ttl_seconds": -5},
            {"human_id": "jalp", "scopes": ["a"], "ttl_seconds": 60, "max_depth": 0},
            {"human_id": "jalp", "scopes": [""], "ttl_seconds": 60},
            {"scopes": ["a"], "ttl_seconds": 60},
        ],
    )
    def test_invalid_payloads_rejected(self, client, admin_headers, payload):
        response = client.post(
            "/api/v1/tokens/root", json=payload, headers=admin_headers
        )
        assert response.status_code == 422, response.text

    def test_unknown_field_rejected(self, client, admin_headers):
        """extra="forbid": a typo'd field must fail loudly, not be ignored."""
        response = client.post(
            "/api/v1/tokens/root",
            json={
                "human_id": "jalp",
                "scopes": ["a"],
                "ttl_seconds": 60,
                "maxDepth": 99,
            },
            headers=admin_headers,
        )
        assert response.status_code == 422

    def test_ttl_capped_at_max(self, adf, container):
        body = adf.mint_root(["read_calendar"], ttl_seconds=999_999_999)
        import jwt

        claims = jwt.decode(body["token"], options={"verify_signature": False})
        assert claims["exp"] - claims["iat"] <= container.settings.max_ttl_seconds


class TestDelegateEndpoint:
    def test_201_response_shape(self, adf):
        root = adf.mint_root(["read_calendar"])
        body = adf.delegate_ok(root["token"], "calendar-agent", ["read_calendar"])
        assert set(body) >= {"token", "jti", "scopes", "approval_required"}
        assert body["scopes"] == ["read_calendar"]
        assert body["depth"] == 1

    def test_403_body_matches_prd(self, adf):
        """PRD 6.2 documents this body exactly; consumers may parse it."""
        root = adf.mint_root(["send_email"])
        response = adf.delegate(root["token"], "web-agent", ["web_search"])
        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail == {
            "error": "scope_escalation_denied",
            "requested": ["web_search"],
            "allowed_max": ["send_email"],
            "denied_scopes": ["web_search"],
        }

    def test_202_body_matches_prd(self, adf):
        root = adf.mint_root(["send_email"])
        response = adf.delegate(root["token"], "email-agent", ["send_email"])
        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "pending_approval"
        assert "send_email requires human approval" in body["message"]
        assert isinstance(body["approval_id"], str)

    def test_malformed_bearer_rejected(self, client):
        response = client.post(
            "/api/v1/tokens/delegate",
            json={
                "child_agent_id": "x",
                "requested_scopes": ["a"],
                "ttl_seconds": 60,
            },
            headers={"Authorization": "NotBearer abc"},
        )
        assert response.status_code == 401

    @pytest.mark.parametrize(
        "payload",
        [
            {"child_agent_id": "x", "requested_scopes": [], "ttl_seconds": 60},
            {"child_agent_id": "", "requested_scopes": ["a"], "ttl_seconds": 60},
            {"child_agent_id": "x", "requested_scopes": ["a"], "ttl_seconds": -1},
            {"requested_scopes": ["a"], "ttl_seconds": 60},
        ],
    )
    def test_invalid_payloads_rejected(self, adf, payload):
        root = adf.mint_root(["read_calendar"])
        response = adf.client.post(
            "/api/v1/tokens/delegate",
            json=payload,
            headers={"Authorization": f"Bearer {root['token']}"},
        )
        assert response.status_code == 422


class TestVerifyEndpoint:
    def test_200_response_shape(self, adf):
        root = adf.mint_root(["read_calendar"])
        response = adf.verify(root["token"], "read_calendar")
        assert response.status_code == 200
        body = response.json()
        assert body["valid"] is True
        assert body["remaining_scopes"] == ["read_calendar"]
        assert body["agent_id"].startswith("human:")

    @pytest.mark.parametrize(
        "scenario,expected_reason",
        [
            ("garbage", "invalid_signature"),
            ("wrong_scope", "scope_not_granted"),
        ],
    )
    def test_401_reasons(self, adf, scenario, expected_reason):
        root = adf.mint_root(["read_calendar"])
        token = "not-a-jwt" if scenario == "garbage" else root["token"]
        scope = "read_calendar" if scenario == "garbage" else "web_search"
        response = adf.verify(token, scope)
        assert response.status_code == 401
        assert response.json() == {"valid": False, "reason": expected_reason}

    def test_verify_does_not_require_auth_headers(self, adf):
        """Verification reveals nothing a token holder does not already possess."""
        root = adf.mint_root(["read_calendar"])
        response = adf.client.post(
            "/api/v1/tokens/verify",
            json={"token": root["token"], "required_scope": "read_calendar"},
        )
        assert response.status_code == 200

    def test_empty_token_rejected(self, client):
        response = client.post(
            "/api/v1/tokens/verify", json={"token": "", "required_scope": "a"}
        )
        assert response.status_code == 422


class TestRevokeEndpoint:
    def test_response_shape(self, adf):
        root = adf.mint_root(["read_calendar"])
        adf.delegate_ok(root["token"], "child", ["read_calendar"])
        body = adf.revoke(root["jti"]).json()
        assert body["revoked"] is True
        assert body["subtree_count"] == 2
        assert isinstance(body["latency_ms"], float)


class TestHealthEndpoint:
    def test_health_shape(self, adf):
        body = adf.health()
        assert body["status"] in {"ok", "degraded"}
        assert "circuit" in body and "open" in body["circuit"]
        assert "redis" in body
        assert "counts" in body
        assert "send_email" in body["sensitive_scopes"]

    def test_health_needs_no_auth(self, client):
        assert client.get("/api/v1/health").status_code == 200

    def test_health_available_unprefixed_for_container_probes(self, client):
        assert client.get("/health").status_code == 200

    def test_health_leaks_no_token_material(self, adf):
        root = adf.mint_root(["read_calendar"])
        body = str(adf.health())
        assert root["token"] not in body
        assert "jwt_secret" not in body
        assert "admin_api_key" not in body


class TestAdminEndpoints:
    def test_subjects_requires_admin(self, client):
        assert client.get("/api/v1/admin/subjects").status_code == 401

    def test_subjects_reveals_mapping_to_admin(self, adf, admin_headers):
        adf.mint_root(["read_calendar"], human_id="jalp")
        body = adf.client.get("/api/v1/admin/subjects", headers=admin_headers).json()
        labels = {row["display_label"] for row in body["subjects"]}
        assert "jalp" in labels

    def test_audit_flush_requires_admin(self, client):
        assert client.post("/api/v1/admin/audit/flush").status_code == 401


class TestOpenAPISchema:
    def test_schema_generates(self, client):
        """A broken schema breaks the auto-generated API reference in the README."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        paths = schema["paths"]
        for expected in [
            "/api/v1/tokens/root",
            "/api/v1/tokens/delegate",
            "/api/v1/tokens/verify",
            "/api/v1/tokens/revoke",
            "/api/v1/tokens/approve",
            "/api/v1/tokens/deny",
            "/api/v1/audit/chain/{jti}",
            "/api/v1/audit/log",
            "/api/v1/audit/verify_integrity",
            "/api/v1/health",
        ]:
            assert expected in paths, f"missing documented path: {expected}"
