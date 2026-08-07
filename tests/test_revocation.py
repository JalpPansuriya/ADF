"""Eval item 3: revocation propagation, including subtree kill and cache-loss safety."""

from __future__ import annotations

import statistics

import pytest

from checkpoint_service.db import redis_client
from checkpoint_service.db.session import session_scope

SCOPES = ["read_calendar"]


class TestRevocationPropagation:
    """Eval item 3 -- target: descendants invalid within 50ms of a root revoke."""

    def test_root_revocation_kills_three_level_chain(self, adf):
        chain = adf.build_chain(3, SCOPES)
        root, level1, level2, level3 = chain

        # All four verify before revocation.
        for token in chain:
            assert adf.verify(token["token"], "read_calendar").json()["valid"] is True

        response = adf.revoke(root["jti"], reason="human pulled the plug")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["revoked"] is True
        assert body["subtree_count"] == 4, body
        assert set(body["revoked_jtis"]) == {c["jti"] for c in chain}

        # All four now fail, including the two that were never touched directly.
        for token in chain:
            result = adf.verify(token["token"], "read_calendar")
            assert result.status_code == 401
            assert result.json()["reason"] == "revoked", token["jti"]

    def test_propagation_latency_measured(self, adf, capsys):
        """Measure and report the propagation latency (the PRD asks for a number)."""
        latencies: list[float] = []
        for _ in range(5):
            chain = adf.build_chain(3, SCOPES)
            response = adf.revoke(chain[0]["jti"])
            latencies.append(response.json()["latency_ms"])

        p50 = statistics.median(latencies)
        worst = max(latencies)
        print(
            f"\n[item 3] revocation propagation (3-level chain, 4 tokens): "
            f"p50={p50:.2f}ms max={worst:.2f}ms target=<50ms"
        )
        # Generous ceiling: this reports the real number rather than being tuned
        # to the target. See DECISIONS.md 2026-08-07 (measured vs asserted).
        assert worst < 1000, f"revocation propagation pathologically slow: {worst:.1f}ms"

    def test_revoking_mid_chain_spares_ancestors(self, adf):
        """Revocation must flow downward only."""
        chain = adf.build_chain(3, SCOPES)
        root, level1, level2, level3 = chain

        response = adf.revoke(level2["jti"])
        assert response.json()["subtree_count"] == 2  # level2 + level3

        assert adf.verify(root["token"], "read_calendar").json()["valid"] is True
        assert adf.verify(level1["token"], "read_calendar").json()["valid"] is True
        assert adf.verify(level2["token"], "read_calendar").json()["reason"] == "revoked"
        assert adf.verify(level3["token"], "read_calendar").json()["reason"] == "revoked"

    def test_revocation_kills_siblings_independently(self, adf):
        """Two sibling branches: revoking one must not affect the other."""
        root = adf.mint_root(["read_calendar", "read_email"])
        cal = adf.delegate_ok(root["token"], "calendar-agent", ["read_calendar"])
        mail = adf.delegate_ok(root["token"], "email-reader-agent", ["read_email"])

        adf.revoke(cal["jti"])
        assert adf.verify(cal["token"], "read_calendar").json()["reason"] == "revoked"
        assert adf.verify(mail["token"], "read_email").json()["valid"] is True

    def test_repeat_revocation_is_idempotent(self, adf):
        chain = adf.build_chain(2, SCOPES)
        first = adf.revoke(chain[0]["jti"]).json()
        second = adf.revoke(chain[0]["jti"]).json()
        assert first["subtree_count"] == second["subtree_count"] == 3
        assert adf.verify(chain[-1]["token"], "read_calendar").json()["reason"] == "revoked"

    def test_revoke_requires_admin_key(self, adf, client):
        root = adf.mint_root(SCOPES)
        response = client.post("/api/v1/tokens/revoke", json={"jti": root["jti"]})
        assert response.status_code == 401

    def test_revocation_is_audited_with_subtree(self, adf):
        chain = adf.build_chain(2, SCOPES)
        adf.revoke(chain[0]["jti"], reason="incident-1234")
        entries = adf.audit_log(action="token_revoked")["entries"]
        assert len(entries) == 1
        assert entries[0]["reason"] == "incident-1234"
        assert entries[0]["detail"]["subtree_count"] == 3


class TestRevocationDurability:
    """Redis is a cache, not the source of truth (DECISIONS.md 2026-08-07)."""

    def test_revocation_survives_total_cache_loss(self, adf, container):
        """The single most important durability property in the system.

        PRD 8.4 stores revocation only in Redis. This test simulates the Redis
        restart that design cannot survive: flush the cache entirely and assert
        the revoked token is STILL rejected.
        """
        chain = adf.build_chain(2, SCOPES)
        adf.revoke(chain[0]["jti"])

        # Nuke the cache, exactly as a Redis container restart would.
        cache = redis_client.get_redis()
        assert cache is not None
        cache.flushall()
        assert cache.scard("adf:revoked") == 0, "cache did not actually clear"

        for token in chain:
            result = adf.verify(token["token"], "read_calendar")
            assert result.status_code == 401, (
                "FAIL-OPEN: a revoked token verified as valid after cache loss"
            )
            assert result.json()["reason"] == "revoked"

    def test_startup_rebuilds_cache_from_postgres(self, adf, container):
        chain = adf.build_chain(2, SCOPES)
        adf.revoke(chain[0]["jti"])

        cache = redis_client.get_redis()
        assert cache is not None
        cache.flushall()

        with session_scope() as session:
            restored = container.revocation.rebuild_cache(session)
        assert restored == 3
        assert cache.scard("adf:revoked") == 3

    def test_lookup_falls_back_to_postgres_when_redis_down(self, adf, container):
        """With Redis marked unavailable, correctness must be preserved."""
        chain = adf.build_chain(1, SCOPES)
        adf.revoke(chain[0]["jti"])

        redis_client.mark_unavailable()
        try:
            result = adf.verify(chain[-1]["token"], "read_calendar")
            assert result.status_code == 401
            assert result.json()["reason"] == "revoked"
        finally:
            redis_client.init_redis(
                container.settings.redis_url, client=redis_client.get_redis()
            )

    def test_is_revoked_refuses_to_answer_without_a_fallback(self, container):
        """It must raise rather than guess 'not revoked' -- guessing fails open."""
        redis_client.mark_unavailable()
        try:
            with pytest.raises(RuntimeError, match="would fail open"):
                container.revocation.is_revoked("some-jti", None)
        finally:
            redis_client.init_redis(
                container.settings.redis_url, client=redis_client.get_redis()
            )

    def test_edges_persisted_to_postgres_not_only_cache(self, adf, container):
        from sqlalchemy import select

        from checkpoint_service.models.audit import DelegationEdge

        chain = adf.build_chain(2, SCOPES)
        with session_scope() as session:
            edges = session.execute(
                select(DelegationEdge.parent_jti, DelegationEdge.child_jti)
            ).all()
        pairs = {(p, c) for p, c in edges}
        assert (chain[0]["jti"], chain[1]["jti"]) in pairs
        assert (chain[1]["jti"], chain[2]["jti"]) in pairs


class TestRevocationEdgeCases:
    def test_ancestor_revocation_detected_even_without_edge_row(self, adf, container):
        """Defence in depth: verify also walks the token's own signed chain.

        If an edge row were ever missing (bug, partial write, manual DB surgery),
        the subtree walk would miss a descendant. The chain check in verify()
        catches it because the ancestry is baked into the signed token.
        """
        from sqlalchemy import delete

        from checkpoint_service.models.audit import DelegationEdge

        chain = adf.build_chain(2, SCOPES)
        with session_scope() as session:
            session.execute(delete(DelegationEdge))

        adf.revoke(chain[0]["jti"])
        result = adf.verify(chain[2]["token"], "read_calendar")
        assert result.status_code == 401
        assert result.json()["reason"] == "revoked"

    def test_revoking_unknown_jti_is_harmless(self, adf):
        response = adf.revoke("00000000-0000-0000-0000-000000000000")
        assert response.status_code == 200
        assert response.json()["subtree_count"] == 1
