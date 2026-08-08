"""Revocation: subtree kill, fail-closed behaviour, and ordering guarantees."""

from __future__ import annotations

import pytest

from agperms import Config, Firewall, MemoryStorage, StorageError


class TestSubtreeKill:
    def test_root_revocation_kills_whole_tree(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        a = fw.delegate(root.token, to="a", scopes=["read_calendar"])
        b = fw.delegate(a.token, to="b", scopes=["read_calendar"])
        c = fw.delegate(b.token, to="c", scopes=["read_calendar"])

        for cap in (root, a, b, c):
            assert fw.verify(cap.token, "read_calendar").valid

        result = fw.revoke(root.jti)
        assert result.subtree_count == 4
        assert set(result.revoked_jtis) == {root.jti, a.jti, b.jti, c.jti}

        for cap in (root, a, b, c):
            outcome = fw.verify(cap.token, "read_calendar")
            assert not outcome.valid
            assert outcome.reason == "revoked"

    def test_revocation_flows_downward_only(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        a = fw.delegate(root.token, to="a", scopes=["read_calendar"])
        b = fw.delegate(a.token, to="b", scopes=["read_calendar"])

        result = fw.revoke(a.jti)
        assert set(result.revoked_jtis) == {a.jti, b.jti}
        assert fw.verify(root.token, "read_calendar").valid
        assert not fw.verify(b.token, "read_calendar").valid

    def test_siblings_are_independent(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])
        left = fw.delegate(root.token, to="left", scopes=["read_calendar"])
        right = fw.delegate(root.token, to="right", scopes=["read_email"])

        fw.revoke(left.jti)
        assert not fw.verify(left.token, "read_calendar").valid
        assert fw.verify(right.token, "read_email").valid

    def test_breadth_first_order_is_preserved(self, fw: Firewall):
        """The order is user-visible, so it is part of the contract."""
        root = fw.mint_root(subject="alice", scopes=["s"])
        a = fw.delegate(root.token, to="a", scopes=["s"])
        b = fw.delegate(root.token, to="b", scopes=["s"])
        a1 = fw.delegate(a.token, to="a1", scopes=["s"])

        order = fw.revoke(root.jti).revoked_jtis
        assert order[0] == root.jti
        # Depth-1 siblings precede the depth-2 grandchild.
        assert set(order[1:3]) == {a.jti, b.jti}
        assert order[3] == a1.jti

    def test_repeat_revoke_is_idempotent(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        child = fw.delegate(root.token, to="c", scopes=["s"])
        first = fw.revoke(root.jti)
        second = fw.revoke(root.jti)
        assert first.subtree_count == second.subtree_count == 2

    def test_ancestor_check_survives_missing_edges(self, fw: Firewall):
        """Defence in depth: verify walks the signed chain, not just the edges."""
        root = fw.mint_root(subject="alice", scopes=["s"])
        child = fw.delegate(root.token, to="c", scopes=["s"])
        # Wipe the edge table, simulating a lost write.
        fw.storage._edges.clear()  # type: ignore[attr-defined]
        fw.revoke(root.jti)
        outcome = fw.verify(child.token, "s")
        assert not outcome.valid and outcome.reason == "revoked"

    def test_revocation_is_audited(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["s"])
        fw.delegate(root.token, to="c", scopes=["s"])
        fw.revoke(root.jti, reason="incident-42")
        rows = fw.audit_events(action="revoked")
        assert len(rows) == 1
        assert rows[0]["reason"] == "incident-42"
        assert rows[0]["detail"]["subtree_count"] == 2


class TestFailClosed:
    def test_closed_storage_refuses_to_answer(self):
        """A store that cannot answer must raise, never say 'not revoked'."""
        storage = MemoryStorage()
        storage.close()
        with pytest.raises(StorageError):
            storage.is_revoked("any-jti")

    def test_verify_propagates_storage_failure(self, config: Config):
        """Better a loud failure than a silent allow."""
        storage = MemoryStorage()
        fw = Firewall(config=config, storage=storage)
        root = fw.mint_root(subject="alice", scopes=["s"])
        storage.close()
        with pytest.raises(StorageError):
            fw.verify(root.token, "s")

    def test_memory_storage_advertises_non_durability(self):
        assert MemoryStorage().durable is False


class TestExpiry:
    def test_expired_token_is_refused(self, fw: Firewall, config: Config):
        import jwt

        root = fw.mint_root(subject="alice", scopes=["s"])
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["exp"] = claims["iat"] - 1
        expired = jwt.encode(claims, config.jwt_secret, algorithm="HS256")
        outcome = fw.verify(expired, "s")
        assert not outcome.valid and outcome.reason == "expired"

    def test_missing_token_is_refused_without_raising(self, fw: Firewall):
        outcome = fw.verify(None, "s")
        assert not outcome.valid and outcome.reason == "missing_token"
        outcome = fw.verify("", "s")
        assert not outcome.valid and outcome.reason == "missing_token"

    def test_garbage_token_is_refused(self, fw: Firewall):
        outcome = fw.verify("not-a-jwt", "s")
        assert not outcome.valid and outcome.reason == "invalid_signature"


class TestTokenIsolation:
    def test_token_from_another_deployment_is_refused(self, config: Config):
        a = Firewall(config=config)
        other = Config(
            jwt_secret="a-completely-different-secret-000000000000",
            pii_salt="other-salt",
        )
        b = Firewall(config=other)
        root = a.mint_root(subject="alice", scopes=["s"])
        assert not b.verify(root.token, "s").valid

    def test_two_firewalls_are_independent(self, config: Config):
        """No module-level singletons: two instances share nothing."""
        one = Firewall(config=config, storage=MemoryStorage())
        two = Firewall(config=config, storage=MemoryStorage())
        root = one.mint_root(subject="alice", scopes=["s"])
        one.revoke(root.jti)
        # `two` never saw the revocation, and `one` is unaffected by `two`.
        assert two.storage.is_revoked(root.jti) is False
        assert one.storage.is_revoked(root.jti) is True


class TestClaimSchema:
    def test_injected_claim_is_rejected(self, fw: Firewall, config: Config):
        """A closed schema: an extra claim is an error, not silently ignored."""
        import jwt

        root = fw.mint_root(subject="alice", scopes=["s"])
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["is_admin"] = True
        forged = jwt.encode(claims, config.jwt_secret, algorithm="HS256")
        outcome = fw.verify(forged, "s")
        assert not outcome.valid and outcome.reason == "malformed_token"

    def test_alg_none_is_rejected(self, fw: Firewall):
        import jwt

        root = fw.mint_root(subject="alice", scopes=["s"])
        claims = jwt.decode(root.token, options={"verify_signature": False})
        unsigned = jwt.encode(claims, key="", algorithm="none")
        assert not fw.verify(unsigned, "s").valid

    def test_foreign_issuer_is_rejected(self, fw: Firewall, config: Config):
        import jwt

        root = fw.mint_root(subject="alice", scopes=["s"])
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["iss"] = "somebody-else"
        forged = jwt.encode(claims, config.jwt_secret, algorithm="HS256")
        outcome = fw.verify(forged, "s")
        assert not outcome.valid and outcome.reason == "malformed_token"
