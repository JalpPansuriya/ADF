"""Shared pytest fixtures for the eval harness.

Runs against in-memory SQLite + fakeredis so `pytest -q` needs no Docker daemon.
See DECISIONS.md 2026-08-07 (SQLite + fakeredis) for why, and for the explicit
caveat that a green run here does not prove the Postgres/Redis path.
"""

from __future__ import annotations

import fakeredis
import pytest
from fastapi.testclient import TestClient

from checkpoint_service.config import Settings, reset_settings_cache
from checkpoint_service.container import AppContainer
from checkpoint_service.db.session import dispose_engine
from checkpoint_service.main import create_app

ADMIN_KEY = "test-admin-key-0123456789abcdef"
JWT_SECRET = "test-jwt-secret-0123456789abcdef0123456789abcdef"
PII_SALT = "test-pii-salt-value"

ROOT_SCOPES = [
    "read_calendar",
    "write_calendar",
    "read_email",
    "send_email",
    "web_search",
]


def build_settings(**overrides) -> Settings:
    """Test settings. Secret-strength enforcement stays ON to exercise the real path."""
    values = dict(
        admin_api_key=ADMIN_KEY,
        jwt_secret=JWT_SECRET,
        pii_salt=PII_SALT,
        database_url="sqlite:///:memory:",
        redis_url="redis://localhost:6379/15",
        max_delegation_depth=5,
        approval_timeout_seconds=300,
        # Flush eagerly so tests can assert on audit rows without long sleeps.
        audit_flush_interval_seconds=0.05,
        audit_buffer_max_size=50,
        guardrail_exempt_agents=["bench-agent"],
        cors_origins=["http://localhost:5173"],
        # Policy denials (blocked escalations, revoked tokens) do NOT count
        # toward the breaker in tests. The escalation matrix in eval item 1
        # deliberately issues hundreds of denials; with PRD 8.3's default the
        # breaker would open and mask 403 responses as 503, making the test
        # measure the breaker instead of the subset rule.
        # tests/test_circuit_breaker.py overrides this back to True to exercise
        # the PRD-default behaviour explicitly.
        circuit_count_policy_denials=False,
    )
    values.update(overrides)
    settings = Settings(**values)
    settings.validate_secrets()
    return settings


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def settings() -> Settings:
    return build_settings()


@pytest.fixture
def container(settings: Settings):
    """Isolated container with a fresh in-memory DB and a fake Redis."""
    fake = fakeredis.FakeRedis(decode_responses=True)
    c = AppContainer(settings, redis_override=fake, create_tables=True)
    yield c
    dispose_engine()


@pytest.fixture
def client(container: AppContainer):
    """TestClient bound to the isolated container (runs lifespan hooks)."""
    app = create_app(container)
    with TestClient(app) as test_client:
        test_client.container = container  # type: ignore[attr-defined]
        yield test_client


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"X-Admin-Key": ADMIN_KEY}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class ADFTestHelper:
    """Convenience wrapper over the HTTP API for building token chains."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.admin = {"X-Admin-Key": ADMIN_KEY}

    def mint_root(
        self,
        scopes: list[str] | None = None,
        *,
        human_id: str = "jalp",
        ttl_seconds: int = 3600,
        max_depth: int | None = None,
    ) -> dict:
        body: dict = {
            "human_id": human_id,
            "scopes": scopes if scopes is not None else ROOT_SCOPES,
            "ttl_seconds": ttl_seconds,
        }
        if max_depth is not None:
            body["max_depth"] = max_depth
        response = self.client.post(
            "/api/v1/tokens/root", json=body, headers=self.admin
        )
        assert response.status_code == 201, response.text
        return response.json()

    def delegate(
        self,
        parent_token: str,
        child_agent_id: str,
        requested_scopes: list[str],
        ttl_seconds: int = 600,
    ):
        return self.client.post(
            "/api/v1/tokens/delegate",
            json={
                "child_agent_id": child_agent_id,
                "requested_scopes": requested_scopes,
                "ttl_seconds": ttl_seconds,
            },
            headers={"Authorization": f"Bearer {parent_token}"},
        )

    def delegate_ok(self, *args, **kwargs) -> dict:
        response = self.delegate(*args, **kwargs)
        assert response.status_code == 201, response.text
        return response.json()

    def verify(self, token: str, required_scope: str):
        return self.client.post(
            "/api/v1/tokens/verify",
            json={"token": token, "required_scope": required_scope},
        )

    def revoke(self, jti: str, reason: str | None = None):
        return self.client.post(
            "/api/v1/tokens/revoke",
            json={"jti": jti, "reason": reason},
            headers=self.admin,
        )

    def approve(self, approval_id: str):
        return self.client.post(
            "/api/v1/tokens/approve",
            json={"approval_id": approval_id, "decision": "approve"},
            headers=self.admin,
        )

    def deny(self, approval_id: str):
        return self.client.post(
            "/api/v1/tokens/deny",
            json={"approval_id": approval_id, "decision": "deny"},
            headers=self.admin,
        )

    def collect(self, approval_id: str) -> dict:
        response = self.client.get(f"/api/v1/tokens/pending/{approval_id}")
        assert response.status_code == 200, response.text
        return response.json()

    def chain(self, jti: str) -> dict:
        response = self.client.get(f"/api/v1/audit/chain/{jti}")
        assert response.status_code == 200, response.text
        return response.json()

    def integrity(self) -> dict:
        response = self.client.get("/api/v1/audit/verify_integrity")
        assert response.status_code == 200, response.text
        return response.json()

    def health(self) -> dict:
        response = self.client.get("/api/v1/health")
        assert response.status_code == 200, response.text
        return response.json()

    def audit_log(self, **params) -> dict:
        response = self.client.get("/api/v1/audit/log", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    def flush_audit(self) -> None:
        """Make buffered verify_success rows durable before asserting on them."""
        self.client.container.audit.flush()  # type: ignore[attr-defined]

    def build_chain(self, depth: int, scopes: list[str]) -> list[dict]:
        """Mint a root plus ``depth`` delegated tokens, all holding ``scopes``."""
        root = self.mint_root(scopes)
        chain = [root]
        token = root["token"]
        for level in range(1, depth + 1):
            child = self.delegate_ok(token, f"agent-level-{level}", scopes)
            chain.append(child)
            token = child["token"]
        return chain


@pytest.fixture
def adf(client) -> ADFTestHelper:
    return ADFTestHelper(client)


@pytest.fixture
def bulk_container(settings_bulk):
    """Container with generous rate limits for bulk/matrix tests.

    The aggregate escalation matrix issues several hundred delegations from one
    subject inside a minute, which legitimately exceeds the default 60/min budget.
    Raising the limit for this fixture keeps the matrix measuring the subset rule;
    the default limit is still exercised by tests/test_rate_limit.py.
    """
    fake = fakeredis.FakeRedis(decode_responses=True)
    c = AppContainer(settings_bulk, redis_override=fake, create_tables=True)
    yield c
    dispose_engine()


@pytest.fixture
def settings_bulk() -> Settings:
    return build_settings(
        rate_limit_delegate_per_min=100_000,
        rate_limit_verify_per_min=100_000,
        circuit_volume_ceiling=1_000_000,
    )


@pytest.fixture
def adf_bulk(bulk_container) -> ADFTestHelper:
    app = create_app(bulk_container)
    with TestClient(app) as test_client:
        test_client.container = bulk_container  # type: ignore[attr-defined]
        yield ADFTestHelper(test_client)
