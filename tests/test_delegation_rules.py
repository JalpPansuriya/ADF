"""Eval items 1 & 2: scope escalation always fails, legitimate narrowing always succeeds.

This is the core invariant of the product, so item 1 is parametrized over many
parent/request combinations rather than asserting a single happy path. A single
assertion could pass while the check was subtly wrong (e.g. comparing lengths
instead of membership).
"""

from __future__ import annotations

import itertools

import pytest

from tests.conftest import ROOT_SCOPES

ALL_SCOPES = ROOT_SCOPES


def _subsets(scopes: list[str], sizes: list[int]) -> list[list[str]]:
    out: list[list[str]] = []
    for size in sizes:
        out.extend(sorted(combo) for combo in itertools.combinations(scopes, size))
    return out


# Every (parent_scopes, requested_scopes) pair where the request is NOT a subset.
ESCALATION_CASES: list[tuple[list[str], list[str]]] = []
for _parent in _subsets(ALL_SCOPES, [1, 2, 3]):
    for _requested in _subsets(ALL_SCOPES, [1, 2, 3]):
        if not set(_requested).issubset(set(_parent)):
            ESCALATION_CASES.append((_parent, _requested))

# Every (parent, requested) pair where the request IS a non-empty subset.
NARROWING_CASES: list[tuple[list[str], list[str]]] = []
for _parent in _subsets(ALL_SCOPES, [1, 2, 3]):
    for _requested in _subsets(_parent, list(range(1, len(_parent) + 1))):
        NARROWING_CASES.append((_parent, _requested))


class TestScopeEscalationAlwaysFails:
    """Eval item 1 -- target: 100% block rate, 0 false negatives."""

    @pytest.mark.parametrize("parent_scopes,requested", ESCALATION_CASES)
    def test_superset_request_is_denied(self, adf, parent_scopes, requested):
        root = adf.mint_root(parent_scopes)
        response = adf.delegate(root["token"], "greedy-agent", requested)

        assert response.status_code == 403, (
            f"ESCALATION NOT BLOCKED: parent={parent_scopes} requested={requested} "
            f"-> {response.status_code} {response.text}"
        )
        detail = response.json()["detail"]
        assert detail["error"] == "scope_escalation_denied"
        assert detail["requested"] == sorted(requested)
        assert detail["allowed_max"] == sorted(parent_scopes)
        # denied_scopes must be exactly the offending scopes -- not all requested.
        assert sorted(detail["denied_scopes"]) == sorted(
            set(requested) - set(parent_scopes)
        )

    def test_block_rate_is_total(self, adf_bulk):
        """Aggregate the whole matrix and assert a 100% block rate.

        Uses the high-limit fixture: this issues one delegation per case from a
        single subject, which would otherwise hit the 60/min rate limit and
        measure the limiter rather than the subset rule.
        """
        adf = adf_bulk
        blocked = 0
        for parent_scopes, requested in ESCALATION_CASES:
            root = adf.mint_root(parent_scopes)
            if adf.delegate(root["token"], "greedy-agent", requested).status_code == 403:
                blocked += 1
        total = len(ESCALATION_CASES)
        rate = blocked / total
        print(f"\n[item 1] escalation block rate: {blocked}/{total} = {rate:.1%}")
        assert rate == 1.0, f"false negatives: {total - blocked} of {total}"

    def test_escalation_mints_no_token(self, adf):
        """A denial must not leave a usable credential behind."""
        root = adf.mint_root(["read_calendar"])
        before = adf.health()["counts"]["tokens"]
        response = adf.delegate(root["token"], "greedy-agent", ["web_search"])
        assert response.status_code == 403
        assert "token" not in response.json()
        assert adf.health()["counts"]["tokens"] == before

    def test_escalation_is_audited(self, adf):
        root = adf.mint_root(["read_calendar"])
        adf.delegate(root["token"], "greedy-agent", ["send_email", "web_search"])
        entries = adf.audit_log(action="scope_escalation_denied")["entries"]
        assert len(entries) == 1
        assert sorted(entries[0]["denied_scopes"]) == ["send_email", "web_search"]
        assert entries[0]["decision"] == "deny"

    def test_grandchild_cannot_regain_parent_scope(self, adf):
        """The narrowing must be transitive, not merely one-hop."""
        root = adf.mint_root(["read_calendar", "web_search"])
        child = adf.delegate_ok(root["token"], "mid-agent", ["read_calendar"])
        # mid-agent lost web_search; it must not be able to re-grant it even
        # though the root had it.
        response = adf.delegate(child["token"], "grandchild", ["web_search"])
        assert response.status_code == 403
        assert response.json()["detail"]["denied_scopes"] == ["web_search"]


class TestLegitimateNarrowingAlwaysSucceeds:
    """Eval item 2."""

    @pytest.mark.parametrize("parent_scopes,requested", NARROWING_CASES)
    def test_subset_request_is_allowed(self, adf, parent_scopes, requested):
        root = adf.mint_root(parent_scopes)
        response = adf.delegate(root["token"], "good-agent", requested)

        # A sensitive scope legitimately diverts to the approval gate (202); that
        # is a success for the subset rule, just not an immediate mint.
        assert response.status_code in (201, 202), response.text
        if response.status_code == 201:
            body = response.json()
            assert body["scopes"] == sorted(requested)
            assert body["depth"] == 1

    def test_equal_scopes_allowed(self, adf):
        """PRD 5 rule 1: subset is inclusive -- equal must be permitted."""
        scopes = ["read_calendar", "read_email"]
        root = adf.mint_root(scopes)
        child = adf.delegate_ok(root["token"], "same-agent", scopes)
        assert child["scopes"] == sorted(scopes)

    def test_child_exp_never_exceeds_parent(self, adf):
        """PRD 5 rule 2, tested by requesting a ttl far beyond the parent's."""
        root = adf.mint_root(["read_calendar"], ttl_seconds=60)
        child = adf.delegate_ok(
            root["token"], "greedy-ttl-agent", ["read_calendar"], ttl_seconds=99999
        )
        assert child["expires_at"] <= root["expires_at"], (
            "child outlived its parent: "
            f"child={child['expires_at']} parent={root['expires_at']}"
        )

    def test_depth_increments_and_chain_grows(self, adf):
        chain = adf.build_chain(3, ["read_calendar"])
        assert [c.get("depth", 0) for c in chain[1:]] == [1, 2, 3]

    def test_depth_limit_enforced(self, adf):
        """PRD 5 rule 3."""
        root = adf.mint_root(["read_calendar"], max_depth=2)
        first = adf.delegate_ok(root["token"], "level-1", ["read_calendar"])
        second = adf.delegate_ok(first["token"], "level-2", ["read_calendar"])
        third = adf.delegate(second["token"], "level-3", ["read_calendar"])
        assert third.status_code == 403
        assert third.json()["detail"]["error"] == "depth_limit_exceeded"
        assert third.json()["detail"]["max_depth"] == 2

    def test_child_cannot_raise_max_depth(self, adf):
        """A descendant must inherit the ceiling, never widen it."""
        root = adf.mint_root(["read_calendar"], max_depth=2)
        child = adf.delegate_ok(root["token"], "level-1", ["read_calendar"])
        import jwt

        claims = jwt.decode(child["token"], options={"verify_signature": False})
        assert claims["max_depth"] == 2

    def test_delegation_chain_lineage_in_claims(self, adf):
        import jwt

        root = adf.mint_root(["read_calendar"])
        child = adf.delegate_ok(root["token"], "level-1", ["read_calendar"])
        grandchild = adf.delegate_ok(child["token"], "level-2", ["read_calendar"])

        claims = jwt.decode(grandchild["token"], options={"verify_signature": False})
        chain = claims["delegation_chain"]
        # PRD 5 rule 4: chain = parent's chain + parent's own entry.
        assert [entry["jti"] for entry in chain] == [root["jti"], child["jti"]]
        assert claims["root_jti"] == root["jti"]
        assert claims["depth"] == 2


class TestParentTokenValidation:
    """A delegation is only as trustworthy as the token presented for it."""

    def test_forged_signature_rejected(self, adf):
        import jwt

        root = adf.mint_root(["read_calendar"])
        claims = jwt.decode(root["token"], options={"verify_signature": False})
        claims["scopes"] = ["read_calendar", "send_email", "web_search"]
        forged = jwt.encode(claims, "wrong-secret", algorithm="HS256")

        response = adf.delegate(forged, "attacker-agent", ["web_search"])
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "invalid_signature"

    def test_missing_bearer_token_rejected(self, adf):
        response = adf.client.post(
            "/api/v1/tokens/delegate",
            json={
                "child_agent_id": "x",
                "requested_scopes": ["read_calendar"],
                "ttl_seconds": 60,
            },
        )
        assert response.status_code == 401

    def test_expired_parent_cannot_delegate(self, adf, container):
        """An expired token must not be able to spawn a fresh child."""
        import jwt

        from checkpoint_service.utils import utcnow_ts

        root = adf.mint_root(["read_calendar"])
        claims = jwt.decode(root["token"], options={"verify_signature": False})
        claims["exp"] = utcnow_ts() - 10
        expired = jwt.encode(
            claims, container.settings.jwt_secret, algorithm="HS256"
        )
        response = adf.delegate(expired, "child", ["read_calendar"])
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "expired"

    def test_revoked_parent_cannot_delegate(self, adf):
        root = adf.mint_root(["read_calendar"])
        child = adf.delegate_ok(root["token"], "mid", ["read_calendar"])
        adf.revoke(root["jti"])
        response = adf.delegate(child["token"], "grandchild", ["read_calendar"])
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "revoked"


class TestRootMintAuth:
    def test_root_requires_admin_key(self, client):
        response = client.post(
            "/api/v1/tokens/root",
            json={"human_id": "jalp", "scopes": ["read_calendar"], "ttl_seconds": 60},
        )
        assert response.status_code == 401

    def test_root_rejects_wrong_admin_key(self, client):
        response = client.post(
            "/api/v1/tokens/root",
            json={"human_id": "jalp", "scopes": ["read_calendar"], "ttl_seconds": 60},
            headers={"X-Admin-Key": "wrong-key-but-right-length-000000"},
        )
        assert response.status_code == 401

    def test_root_token_carries_opaque_subject(self, adf):
        """PRD 8.6: no raw human identifier may appear in the token."""
        import jwt

        root = adf.mint_root(["read_calendar"], human_id="jalp")
        claims = jwt.decode(root["token"], options={"verify_signature": False})
        assert "jalp" not in root["token"]
        assert claims["sub"].startswith("human:")
        assert "jalp" not in claims["sub"]
        assert claims["depth"] == 0
