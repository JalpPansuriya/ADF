"""Locust load test for the enforcement checkpoint (PRD eval item 8).

Measures ``/verify`` under real HTTP concurrency, which the in-process pytest
benchmark cannot: that one shares a process with the server and so understates
connection and serialisation costs.

Setup::

    docker compose up -d
    export ADF_ADMIN_API_KEY=<your key>
    locust -f tests/locustfile.py --host http://localhost:8000

Then open http://localhost:8089.

Headless::

    locust -f tests/locustfile.py --host http://localhost:8000 \
        --headless -u 50 -r 10 -t 60s --only-summary

Note: run as an agent listed in ``ADF_GUARDRAIL_EXEMPT_AGENTS`` (default
``bench-agent``), or the 300 verify/min per-agent limit will dominate the result
and you will be benchmarking the rate limiter. Set ``ADF_BENCH_SPREAD=1`` to mint a
distinct identity per user instead, which keeps guardrails fully active at the cost
of measuring per-agent key churn too.
"""

from __future__ import annotations

import os
import uuid

from locust import HttpUser, between, events, task

ADMIN_KEY = os.getenv("ADF_ADMIN_API_KEY", "")
BENCH_AGENT = os.getenv("ADF_BENCH_AGENT", "bench-agent")
SPREAD = os.getenv("ADF_BENCH_SPREAD", "").strip() in {"1", "true", "yes"}
SCOPES = ["read_calendar", "read_email", "web_search"]


@events.test_start.add_listener
def _warn_about_admin_key(**_kwargs):
    if not ADMIN_KEY:
        print(
            "WARNING: ADF_ADMIN_API_KEY is not set, so root tokens cannot be minted "
            "and every task will fail. Export it before running."
        )


class CheckpointUser(HttpUser):
    """Simulates an agent calling the checkpoint before each action."""

    wait_time = between(0.0, 0.05)

    def on_start(self) -> None:
        self.token: str | None = None
        self.revoked_token: str | None = None

        human_id = BENCH_AGENT if not SPREAD else f"{BENCH_AGENT}-{uuid.uuid4().hex[:8]}"
        agent_id = human_id

        response = self.client.post(
            "/api/v1/tokens/root",
            json={"human_id": human_id, "scopes": SCOPES, "ttl_seconds": 3600},
            headers={"X-Admin-Key": ADMIN_KEY},
            name="/tokens/root (setup)",
        )
        if response.status_code != 201:
            return
        root_token = response.json()["token"]

        child = self.client.post(
            "/api/v1/tokens/delegate",
            json={
                "child_agent_id": agent_id,
                "requested_scopes": ["read_calendar"],
                "ttl_seconds": 3600,
            },
            headers={"Authorization": f"Bearer {root_token}"},
            name="/tokens/delegate (setup)",
        )
        if child.status_code == 201:
            self.token = child.json()["token"]

        # A pre-revoked token so the revocation-lookup path is measured too.
        doomed = self.client.post(
            "/api/v1/tokens/delegate",
            json={
                "child_agent_id": f"{agent_id}-doomed",
                "requested_scopes": ["read_calendar"],
                "ttl_seconds": 3600,
            },
            headers={"Authorization": f"Bearer {root_token}"},
            name="/tokens/delegate (setup)",
        )
        if doomed.status_code == 201:
            body = doomed.json()
            self.revoked_token = body["token"]
            self.client.post(
                "/api/v1/tokens/revoke",
                json={"jti": body["jti"], "reason": "load test fixture"},
                headers={"X-Admin-Key": ADMIN_KEY},
                name="/tokens/revoke (setup)",
            )

    @task(20)
    def verify_valid(self) -> None:
        """The dominant production pattern: a valid token, granted scope."""
        if not self.token:
            return
        with self.client.post(
            "/api/v1/tokens/verify",
            json={"token": self.token, "required_scope": "read_calendar"},
            name="/tokens/verify (allow)",
            catch_response=True,
        ) as response:
            if response.status_code == 200 and response.json().get("valid"):
                response.success()
            else:
                response.failure(f"unexpected: {response.status_code} {response.text[:120]}")

    @task(3)
    def verify_missing_scope(self) -> None:
        if not self.token:
            return
        with self.client.post(
            "/api/v1/tokens/verify",
            json={"token": self.token, "required_scope": "web_search"},
            name="/tokens/verify (deny: scope)",
            catch_response=True,
        ) as response:
            # A 401 is the CORRECT answer here, so it must not count as a failure.
            if response.status_code == 401:
                response.success()
            else:
                response.failure(f"expected 401, got {response.status_code}")

    @task(2)
    def verify_revoked(self) -> None:
        if not self.revoked_token:
            return
        with self.client.post(
            "/api/v1/tokens/verify",
            json={"token": self.revoked_token, "required_scope": "read_calendar"},
            name="/tokens/verify (deny: revoked)",
            catch_response=True,
        ) as response:
            if response.status_code == 401 and response.json().get("reason") == "revoked":
                response.success()
            else:
                response.failure(f"revoked token not rejected: {response.status_code}")

    @task(1)
    def health(self) -> None:
        self.client.get("/api/v1/health", name="/health")
