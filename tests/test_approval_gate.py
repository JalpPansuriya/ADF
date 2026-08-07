"""Eval item 7: the human-approval gate blocks until a human acts.

The central assertion is that **no usable credential exists** while a request is
pending -- not merely that a flag is set. See DECISIONS.md 2026-08-07 (approval
gate mints on approval).
"""

from __future__ import annotations

import datetime as _dt

import pytest
from sqlalchemy import select, update

from checkpoint_service.db.session import session_scope
from checkpoint_service.models.audit import PendingApproval, TokenRecord


class TestApprovalGateBlocks:
    """Eval item 7."""

    def test_sensitive_scope_returns_202_and_no_token(self, adf):
        root = adf.mint_root(["read_calendar", "send_email"])
        response = adf.delegate(root["token"], "email-agent", ["send_email"])

        assert response.status_code == 202, response.text
        body = response.json()
        assert body["status"] == "pending_approval"
        assert body["sensitive_scopes"] == ["send_email"]
        assert "approval_id" in body
        # The whole point: nothing usable is handed back.
        assert "token" not in body

    def test_no_token_record_is_created_while_pending(self, adf):
        root = adf.mint_root(["send_email"])
        before = adf.health()["counts"]["tokens"]
        adf.delegate(root["token"], "email-agent", ["send_email"])
        assert adf.health()["counts"]["tokens"] == before

    def test_polling_while_pending_yields_no_token(self, adf):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        pending = adf.collect(approval_id)
        assert pending["status"] == "pending"
        assert pending["token"] is None

    def test_non_sensitive_scope_bypasses_the_gate(self, adf):
        root = adf.mint_root(["read_calendar", "send_email"])
        response = adf.delegate(root["token"], "calendar-agent", ["read_calendar"])
        assert response.status_code == 201
        assert response.json()["approval_required"] is False

    def test_mixed_request_still_requires_approval(self, adf):
        """One sensitive scope in the set gates the whole request."""
        root = adf.mint_root(["read_calendar", "send_email"])
        response = adf.delegate(
            root["token"], "mixed-agent", ["read_calendar", "send_email"]
        )
        assert response.status_code == 202
        assert response.json()["sensitive_scopes"] == ["send_email"]

    def test_escalation_beats_approval_gate(self, adf):
        """A scope the parent lacks is denied outright, never queued.

        Ordering matters: queueing an escalation for human review would invite a
        human to approve something the delegating agent had no right to grant.
        """
        root = adf.mint_root(["read_calendar"])
        response = adf.delegate(root["token"], "email-agent", ["send_email"])
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "scope_escalation_denied"


class TestApprovalGrants:
    def test_token_usable_only_after_approval(self, adf):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]

        approved = adf.approve(approval_id)
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"

        collected = adf.collect(approval_id)
        assert collected["status"] == "approved"
        assert collected["token"]

        result = adf.verify(collected["token"], "send_email")
        assert result.status_code == 200
        assert result.json()["valid"] is True

    def test_approved_token_records_the_approver(self, adf):
        import jwt

        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        adf.approve(approval_id)
        token = adf.collect(approval_id)["token"]

        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["approval_required"] is True
        assert claims["approved_by"] == "human:admin"

    def test_approved_child_cannot_outlive_parent(self, adf):
        """The exp ceiling comes from the stored parent_exp, not approval time.

        Without this, a slow approval would silently extend the child's life
        beyond its parent's.
        """
        root = adf.mint_root(["send_email"], ttl_seconds=120)
        approval_id = adf.delegate(
            root["token"], "email-agent", ["send_email"], ttl_seconds=99999
        ).json()["approval_id"]
        adf.approve(approval_id)
        child_jti = adf.collect(approval_id)["jti"]

        with session_scope() as session:
            child = session.get(TokenRecord, child_jti)
            parent = session.get(TokenRecord, root["jti"])
            assert child is not None and parent is not None
            assert child.expires_at <= parent.expires_at

    def test_approval_requires_admin_key(self, adf, client):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        response = client.post(
            "/api/v1/tokens/approve", json={"approval_id": approval_id}
        )
        assert response.status_code == 401

    def test_double_approval_is_rejected(self, adf):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        assert adf.approve(approval_id).status_code == 200
        second = adf.approve(approval_id)
        assert second.status_code == 409

    def test_approval_is_audited(self, adf):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        adf.approve(approval_id)

        pending_events = adf.audit_log(action="approval_pending")["entries"]
        granted_events = adf.audit_log(action="approval_granted")["entries"]
        assert len(pending_events) == 1
        assert len(granted_events) == 1
        assert granted_events[0]["actor_id"] == "human:admin"


class TestApprovalDenials:
    def test_denied_request_never_yields_a_token(self, adf):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]

        denied = adf.deny(approval_id)
        assert denied.status_code == 200
        assert denied.json()["status"] == "denied"
        assert denied.json()["child_jti"] is None

        collected = adf.collect(approval_id)
        assert collected["status"] == "denied"
        assert collected["token"] is None

    def test_approve_endpoint_honours_deny_decision(self, adf):
        """decision="deny" on /approve must deny, not approve."""
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        response = adf.client.post(
            "/api/v1/tokens/approve",
            json={"approval_id": approval_id, "decision": "deny"},
            headers=adf.admin,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "denied"
        assert adf.collect(approval_id)["token"] is None

    def test_cannot_approve_after_denial(self, adf):
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        adf.deny(approval_id)
        assert adf.approve(approval_id).status_code == 409

    def test_unknown_approval_id_returns_404(self, adf):
        assert adf.approve("no-such-approval").status_code == 404


class TestApprovalExpiry:
    def test_stale_request_expires_and_mints_nothing(self, adf):
        """PRD 8.2: requests expire after the timeout if no human acts."""
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]

        # Backdate the deadline rather than sleeping for the real timeout.
        with session_scope() as session:
            session.execute(
                update(PendingApproval)
                .where(PendingApproval.approval_id == approval_id)
                .values(
                    expires_at=_dt.datetime.now(_dt.timezone.utc)
                    - _dt.timedelta(seconds=1)
                )
            )

        collected = adf.collect(approval_id)
        assert collected["status"] == "expired"
        assert collected["token"] is None
        assert adf.approve(approval_id).status_code == 409

    def test_approval_deadline_never_exceeds_parent_expiry(self, adf):
        """A gate that outlives its parent could mint against a dead token."""
        root = adf.mint_root(["send_email"], ttl_seconds=30)
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        with session_scope() as session:
            record = session.get(PendingApproval, approval_id)
            assert record is not None
            assert int(record.expires_at.timestamp()) <= record.parent_exp

    def test_revoked_parent_blocks_approval(self, adf):
        """The parent may die while the request sits in the queue."""
        root = adf.mint_root(["send_email"])
        approval_id = adf.delegate(root["token"], "email-agent", ["send_email"]).json()[
            "approval_id"
        ]
        adf.revoke(root["jti"])

        response = adf.approve(approval_id)
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "revoked"
        assert adf.collect(approval_id)["token"] is None


class TestApprovalsQueueView:
    def test_queue_lists_pending_requests(self, adf):
        root = adf.mint_root(["send_email", "spend_money"])
        adf.delegate(root["token"], "email-agent", ["send_email"])
        adf.delegate(root["token"], "payment-agent", ["spend_money"])

        queue = adf.client.get(
            "/api/v1/audit/approvals", params={"status": "pending"}
        ).json()
        assert queue["total"] == 2
        agents = {row["child_agent_id"] for row in queue["approvals"]}
        assert agents == {"email-agent", "payment-agent"}
