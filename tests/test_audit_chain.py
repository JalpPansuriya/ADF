"""Eval item 4: chain reconstruction accuracy.

The lineage returned by ``/audit/chain/{jti}`` must exactly match the real mint
history. Crucially it is rebuilt from server-side records, so this also verifies
that a caller cannot fabricate its own provenance.
"""

from __future__ import annotations

import jwt


class TestChainReconstruction:
    """Eval item 4."""

    def test_chain_matches_mint_history_exactly(self, adf):
        root = adf.mint_root(["read_calendar", "read_email"], human_id="jalp")
        mid = adf.delegate_ok(root["token"], "assistant-agent", ["read_calendar"])
        leaf = adf.delegate_ok(mid["token"], "calendar-agent", ["read_calendar"])

        chain = adf.chain(leaf["jti"])
        assert [entry["jti"] for entry in chain["chain"]] == [
            root["jti"],
            mid["jti"],
            leaf["jti"],
        ]
        assert [entry["depth"] for entry in chain["chain"]] == [0, 1, 2]
        assert chain["chain"][0]["scopes"] == ["read_calendar", "read_email"]
        assert chain["chain"][-1]["scopes"] == ["read_calendar"]
        assert chain["depth"] == 2
        assert chain["revoked"] is False
        assert chain["expired"] is False

    def test_chain_scopes_are_monotonically_narrowing(self, adf):
        """A rendered chain must never show a scope set widening down the tree."""
        root = adf.mint_root(["read_calendar", "read_email", "web_search"])
        a = adf.delegate_ok(root["token"], "agent-a", ["read_calendar", "read_email"])
        b = adf.delegate_ok(a["token"], "agent-b", ["read_calendar"])

        chain = adf.chain(b["jti"])
        scope_sets = [set(entry["scopes"]) for entry in chain["chain"]]
        for parent, child in zip(scope_sets, scope_sets[1:]):
            assert child.issubset(parent), f"{child} is not a subset of {parent}"

    def test_reconstruction_matches_signed_claim(self, adf):
        """Server-side rebuild and the signed delegation_chain must agree.

        Two independent representations of the same fact; a mismatch means one of
        them is wrong.
        """
        root = adf.mint_root(["read_calendar"])
        mid = adf.delegate_ok(root["token"], "mid-agent", ["read_calendar"])
        leaf = adf.delegate_ok(mid["token"], "leaf-agent", ["read_calendar"])

        claims = jwt.decode(leaf["token"], options={"verify_signature": False})
        claim_jtis = [entry["jti"] for entry in claims["delegation_chain"]]
        rebuilt = [entry["jti"] for entry in adf.chain(leaf["jti"])["chain"]]

        # The claim holds ancestors only; the rebuild includes the leaf itself.
        assert rebuilt == claim_jtis + [leaf["jti"]]

    def test_chain_reveals_revoked_ancestor(self, adf):
        root = adf.mint_root(["read_calendar"])
        mid = adf.delegate_ok(root["token"], "mid-agent", ["read_calendar"])
        adf.revoke(root["jti"])

        chain = adf.chain(mid["jti"])
        assert chain["chain"][0]["revoked"] is True
        assert chain["chain"][1]["revoked"] is True
        assert chain["revoked"] is True

    def test_chain_labels_resolve_opaque_subjects(self, adf):
        """Opaque ids in tokens, readable labels only via the server (PRD 8.6)."""
        root = adf.mint_root(["read_calendar"], human_id="jalp")
        mid = adf.delegate_ok(root["token"], "assistant-agent", ["read_calendar"])

        chain = adf.chain(mid["jti"])
        assert chain["chain"][0]["agent_id"].startswith("human:")
        assert chain["chain"][0]["display_label"] == "jalp"
        assert chain["chain"][1]["display_label"] == "assistant-agent"
        # The opaque id must not embed the readable label.
        assert "jalp" not in chain["chain"][0]["agent_id"]

    def test_unknown_jti_returns_404(self, client):
        response = client.get("/api/v1/audit/chain/does-not-exist")
        assert response.status_code == 404

    def test_deep_chain_reconstructs_fully(self, adf):
        chain_tokens = adf.build_chain(4, ["read_calendar"])
        rebuilt = adf.chain(chain_tokens[-1]["jti"])
        assert len(rebuilt["chain"]) == 5
        assert [e["depth"] for e in rebuilt["chain"]] == [0, 1, 2, 3, 4]


class TestDelegationTree:
    def test_tree_groups_siblings_under_root(self, adf):
        root = adf.mint_root(["read_calendar", "read_email"])
        adf.delegate_ok(root["token"], "calendar-agent", ["read_calendar"])
        adf.delegate_ok(root["token"], "email-reader", ["read_email"])

        tree = adf.client.get("/api/v1/audit/tree").json()
        assert tree["node_count"] == 3
        assert len(tree["roots"]) == 1
        assert len(tree["roots"][0]["children"]) == 2

    def test_tree_marks_revoked_subtree(self, adf):
        root = adf.mint_root(["read_calendar"])
        child = adf.delegate_ok(root["token"], "calendar-agent", ["read_calendar"])
        adf.revoke(root["jti"])

        tree = adf.client.get("/api/v1/audit/tree").json()
        node = tree["roots"][0]
        assert node["revoked"] is True
        assert node["children"][0]["revoked"] is True
        assert node["children"][0]["jti"] == child["jti"]


class TestAuditLogQuery:
    def test_filter_by_action_and_decision(self, adf):
        root = adf.mint_root(["read_calendar"])
        adf.delegate(root["token"], "greedy", ["web_search"])
        adf.delegate_ok(root["token"], "good", ["read_calendar"])

        denied = adf.audit_log(action="scope_escalation_denied")
        assert denied["total"] == 1
        allowed = adf.audit_log(action="token_minted")
        assert allowed["total"] == 1
        assert allowed["entries"][0]["decision"] == "allow"

    def test_verify_success_is_recorded_after_flush(self, adf):
        """Buffered events become durable on flush (DECISIONS.md 2026-08-07)."""
        root = adf.mint_root(["read_calendar"])
        adf.verify(root["token"], "read_calendar")
        adf.flush_audit()

        entries = adf.audit_log(action="verify_success")["entries"]
        assert len(entries) == 1
        assert entries[0]["required_scope"] == "read_calendar"
        assert entries[0]["latency_ms"] is not None

    def test_pagination(self, adf):
        root = adf.mint_root(["read_calendar"])
        for i in range(5):
            adf.delegate_ok(root["token"], f"agent-{i}", ["read_calendar"])
        page = adf.audit_log(action="token_minted", limit=2, offset=0)
        assert page["total"] == 5
        assert len(page["entries"]) == 2

    def test_audit_never_stores_raw_human_id(self, adf):
        """PRD 8.6: the raw identifier must not appear anywhere in the log."""
        adf.mint_root(["read_calendar"], human_id="jalp")
        entries = adf.audit_log()["entries"]
        serialised = str(entries)
        assert "jalp" not in serialised
        root_event = [e for e in entries if e["action"] == "root_token_minted"][0]
        assert root_event["actor_id"].startswith("human:")
        # The salted hash is what gets persisted for correlation.
        assert len(root_event["actor_id"]) > 10
