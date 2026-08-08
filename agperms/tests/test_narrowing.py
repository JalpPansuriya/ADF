"""Capability narrowing: the invariant the library exists to enforce.

Item 1 is parametrized over every non-subset combination rather than asserting a
single happy path, because a subset check can be subtly wrong (comparing lengths,
comparing the request against itself) and still pass one example.
"""

from __future__ import annotations

import itertools

import jwt
import pytest

from agperms import (
    ApprovalRequired,
    DepthLimitExceeded,
    Firewall,
    ParentTokenInvalid,
    RootChainBroken,
    ScopeEscalationDenied,
)

SCOPES = ["read_calendar", "write_calendar", "read_email", "web_search"]


def _subsets(scopes: list[str], sizes: list[int]) -> list[list[str]]:
    out: list[list[str]] = []
    for size in sizes:
        out.extend(sorted(combo) for combo in itertools.combinations(scopes, size))
    return out


ESCALATIONS: list[tuple[list[str], list[str]]] = [
    (parent, requested)
    for parent in _subsets(SCOPES, [1, 2, 3])
    for requested in _subsets(SCOPES, [1, 2, 3])
    if not set(requested).issubset(parent)
]

NARROWINGS: list[tuple[list[str], list[str]]] = [
    (parent, requested)
    for parent in _subsets(SCOPES, [1, 2, 3])
    for requested in _subsets(parent, list(range(1, len(parent) + 1)))
]


class TestEscalationAlwaysFails:
    @pytest.mark.parametrize("parent_scopes,requested", ESCALATIONS)
    def test_superset_request_is_denied(self, fw: Firewall, parent_scopes, requested):
        root = fw.mint_root(subject="alice", scopes=parent_scopes)
        with pytest.raises(ScopeEscalationDenied) as exc:
            fw.delegate(root.token, to="greedy", scopes=requested)
        assert exc.value.denied_scopes == sorted(set(requested) - set(parent_scopes))
        assert exc.value.allowed_max == sorted(parent_scopes)

    def test_block_rate_is_total(self, fw: Firewall):
        blocked = 0
        for parent_scopes, requested in ESCALATIONS:
            root = fw.mint_root(subject="alice", scopes=parent_scopes)
            try:
                fw.delegate(root.token, to="greedy", scopes=requested)
            except ScopeEscalationDenied:
                blocked += 1
        total = len(ESCALATIONS)
        print(f"\n[narrowing] block rate: {blocked}/{total}")
        assert blocked == total, f"{total - blocked} escalations slipped through"

    def test_denial_mints_nothing(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        before = fw.storage.count_audit_rows()
        with pytest.raises(ScopeEscalationDenied):
            fw.delegate(root.token, to="greedy", scopes=["web_search"])
        # An audit row is written (the denial), but no token was created.
        assert fw.audit_events(action="delegated") == []
        assert fw.storage.count_audit_rows() > before

    def test_narrowing_is_transitive(self, fw: Firewall):
        """A grandchild cannot regain a scope its parent dropped."""
        root = fw.mint_root(subject="alice", scopes=["read_calendar", "web_search"])
        mid = fw.delegate(root.token, to="mid", scopes=["read_calendar"])
        with pytest.raises(ScopeEscalationDenied) as exc:
            fw.delegate(mid.token, to="grandchild", scopes=["web_search"])
        assert exc.value.denied_scopes == ["web_search"]

    def test_escalation_is_audited(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        with pytest.raises(ScopeEscalationDenied):
            fw.delegate(root.token, to="greedy", scopes=["web_search", "read_email"])
        rows = fw.audit_events(action="escalation_denied")
        assert len(rows) == 1
        assert sorted(rows[0]["denied_scopes"]) == ["read_email", "web_search"]


class TestLegitimateNarrowing:
    @pytest.mark.parametrize("parent_scopes,requested", NARROWINGS)
    def test_subset_request_allowed(self, fw: Firewall, parent_scopes, requested):
        root = fw.mint_root(subject="alice", scopes=parent_scopes)
        child = fw.delegate(root.token, to="good", scopes=requested)
        assert child.scopes == tuple(sorted(requested))
        assert child.depth == 1

    def test_equal_scopes_allowed(self, fw: Firewall):
        """Subset is inclusive: equal must be permitted."""
        scopes = ["read_calendar", "read_email"]
        root = fw.mint_root(subject="alice", scopes=scopes)
        child = fw.delegate(root.token, to="same", scopes=scopes)
        assert child.scopes == tuple(sorted(scopes))

    def test_child_never_outlives_parent(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"], ttl_seconds=60)
        child = fw.delegate(
            root.token, to="greedy-ttl", scopes=["read_calendar"], ttl_seconds=99_999
        )
        assert child.claims.exp <= root.claims.exp

    def test_depth_ceiling_enforced(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"], max_depth=2)
        one = fw.delegate(root.token, to="l1", scopes=["read_calendar"])
        two = fw.delegate(one.token, to="l2", scopes=["read_calendar"])
        with pytest.raises(DepthLimitExceeded) as exc:
            fw.delegate(two.token, to="l3", scopes=["read_calendar"])
        assert exc.value.max_depth == 2

    def test_child_cannot_widen_max_depth(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"], max_depth=2)
        child = fw.delegate(root.token, to="l1", scopes=["read_calendar"])
        assert child.claims.max_depth == 2

    def test_chain_records_every_hop(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        mid = fw.delegate(root.token, to="mid", scopes=["read_calendar"])
        leaf = fw.delegate(mid.token, to="leaf", scopes=["read_calendar"])
        assert leaf.claims.ancestor_jtis == (root.jti, mid.jti)
        assert leaf.claims.root_jti == root.jti
        assert leaf.claims.depth == 2


class TestParentValidation:
    def test_forged_signature_cannot_delegate(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["scopes"] = ["read_calendar", "web_search"]
        forged = jwt.encode(claims, "wrong-secret", algorithm="HS256")
        with pytest.raises(ParentTokenInvalid) as exc:
            fw.delegate(forged, to="attacker", scopes=["web_search"])
        assert exc.value.reason == "invalid_signature"

    def test_revoked_parent_cannot_delegate(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        child = fw.delegate(root.token, to="mid", scopes=["read_calendar"])
        fw.revoke(root.jti)
        with pytest.raises(ParentTokenInvalid) as exc:
            fw.delegate(child.token, to="grandchild", scopes=["read_calendar"])
        assert exc.value.reason == "revoked"

    def test_expired_parent_cannot_delegate(self, fw: Firewall, config):
        import agperms._tokens as tokens_mod

        root = fw.mint_root(subject="alice", scopes=["read_calendar"], ttl_seconds=1)
        # Forge an expired-but-correctly-signed token rather than sleeping.
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["exp"] = claims["iat"] - 10
        expired = jwt.encode(claims, config.jwt_secret, algorithm="HS256")
        with pytest.raises(ParentTokenInvalid) as exc:
            fw.delegate(expired, to="child", scopes=["read_calendar"])
        assert exc.value.reason == "expired"

    def test_unknown_root_is_rejected(self, fw: Firewall, config):
        """A well-signed token whose root was never recorded must not delegate."""
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["root_jti"] = "00000000-0000-0000-0000-000000000000"
        claims["depth"] = 1
        orphan = jwt.encode(claims, config.jwt_secret, algorithm="HS256")
        with pytest.raises(RootChainBroken):
            fw.delegate(orphan, to="child", scopes=["read_calendar"])


class TestApprovalGate:
    def test_sensitive_scope_parks_without_minting(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["send_email"])
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        assert exc.value.sensitive_scopes == ["send_email"]
        assert fw.audit_events(action="delegated") == []

    def test_approval_mints_and_collects(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["send_email"])
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        approval_id = exc.value.approval_id

        assert fw.collect(approval_id) is None  # nothing yet

        cap = fw.approve(approval_id, approver="human:alice")
        assert cap.scopes == ("send_email",)
        assert cap.claims.approval_required is True
        assert cap.claims.approved_by == "human:alice"
        assert fw.verify(cap.token, "send_email").valid

        collected = fw.collect(approval_id)
        assert collected is not None and collected.jti == cap.jti

    def test_denied_approval_never_mints(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["send_email"])
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        fw.deny(exc.value.approval_id, approver="human:alice", reason="not needed")
        from agperms import Denied

        with pytest.raises(Denied):
            fw.collect(exc.value.approval_id)

    def test_escalation_beats_approval_gate(self, fw: Firewall):
        """A scope the parent lacks is refused outright, never queued for a human."""
        root = fw.mint_root(subject="alice", scopes=["read_calendar"])
        with pytest.raises(ScopeEscalationDenied):
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        assert fw.pending_approvals() == []

    def test_revoked_parent_blocks_approval(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["send_email"])
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(root.token, to="email-agent", scopes=["send_email"])
        fw.revoke(root.jti)
        with pytest.raises(ParentTokenInvalid):
            fw.approve(exc.value.approval_id, approver="human:alice")

    def test_approved_child_cannot_outlive_parent(self, fw: Firewall):
        root = fw.mint_root(subject="alice", scopes=["send_email"], ttl_seconds=120)
        with pytest.raises(ApprovalRequired) as exc:
            fw.delegate(
                root.token, to="email-agent", scopes=["send_email"], ttl_seconds=99_999
            )
        cap = fw.approve(exc.value.approval_id, approver="human:alice")
        assert cap.claims.exp <= root.claims.exp


class TestPrivacy:
    def test_raw_identifier_never_enters_the_token(self, fw: Firewall):
        root = fw.mint_root(subject="alice@example.com", scopes=["read_calendar"])
        assert "alice@example.com" not in root.token
        assert root.claims.sub.startswith("human:")
        assert "alice" not in root.claims.sub

    def test_raw_identifier_never_enters_the_audit_log(self, fw: Firewall):
        fw.mint_root(subject="alice@example.com", scopes=["read_calendar"])
        assert "alice@example.com" not in str(fw.audit_events())

    def test_same_identifier_resolves_to_one_subject(self, fw: Firewall):
        a = fw.mint_root(subject="alice", scopes=["read_calendar"])
        b = fw.mint_root(subject="alice", scopes=["read_email"])
        assert a.claims.sub == b.claims.sub
