"""F02: Token Engine unit tests -- minting, decoding, and claim integrity.

These are the lowest-level guarantees the rest of the system rests on, so they are
tested directly against the engine rather than through HTTP.
"""

from __future__ import annotations

import jwt
import pytest

from checkpoint_service.engine.token_engine import (
    REASON_EXPIRED,
    REASON_INVALID_SIGNATURE,
    REASON_MALFORMED,
    TokenEngine,
    TokenError,
)
from checkpoint_service.models.token import TokenClaims
from checkpoint_service.utils import utcnow_ts
from tests.conftest import build_settings


@pytest.fixture
def engine():
    return TokenEngine(build_settings())


@pytest.fixture
def root(engine):
    return engine.mint_root(
        subject_id="human:abc",
        scopes=["read_calendar", "send_email"],
        ttl_seconds=600,
        max_depth=5,
    )


class TestRootMinting:
    def test_root_claims(self, root):
        claims = root.claims
        assert claims.depth == 0
        assert claims.max_depth == 5
        assert claims.delegation_chain == []
        assert claims.root_jti == claims.jti  # a root is its own chain terminus
        assert claims.issued_for == claims.sub
        assert claims.iss == "checkpoint-service"
        assert claims.approval_required is False

    def test_scopes_are_sorted_and_deduped(self, engine):
        minted = engine.mint_root(
            subject_id="human:abc",
            scopes=["web_search", "read_calendar", "web_search"],
            ttl_seconds=60,
            max_depth=5,
        )
        assert minted.claims.scopes == ["read_calendar", "web_search"]

    def test_exp_respects_ttl(self, engine):
        minted = engine.mint_root(
            subject_id="human:abc", scopes=["a"], ttl_seconds=100, max_depth=5
        )
        assert 95 <= minted.claims.exp - utcnow_ts() <= 100

    def test_jti_is_unique(self, engine):
        jtis = {
            engine.mint_root(
                subject_id="human:abc", scopes=["a"], ttl_seconds=60, max_depth=5
            ).jti
            for _ in range(50)
        }
        assert len(jtis) == 50


class TestChildMinting:
    def test_child_inherits_and_narrows(self, engine, root):
        child = engine.mint_child(
            parent=root.claims,
            child_subject_id="agent:xyz",
            scopes=["read_calendar"],
            exp=root.claims.exp,
        )
        claims = child.claims
        assert claims.scopes == ["read_calendar"]
        assert claims.depth == 1
        assert claims.max_depth == root.claims.max_depth
        assert claims.root_jti == root.claims.jti
        assert claims.issued_for == f"agent:{root.claims.jti}"

    def test_chain_appends_parent_entry(self, engine, root):
        child = engine.mint_child(
            parent=root.claims,
            child_subject_id="agent:xyz",
            scopes=["read_calendar"],
            exp=root.claims.exp,
        )
        assert len(child.claims.delegation_chain) == 1
        entry = child.claims.delegation_chain[0]
        assert entry.jti == root.claims.jti
        assert entry.agent_id == root.claims.sub
        # The entry records what the parent held AT GRANT TIME.
        assert entry.scopes == root.claims.scopes

        grandchild = engine.mint_child(
            parent=child.claims,
            child_subject_id="agent:deep",
            scopes=["read_calendar"],
            exp=child.claims.exp,
        )
        assert [e.jti for e in grandchild.claims.delegation_chain] == [
            root.claims.jti,
            child.claims.jti,
        ]

    def test_max_depth_is_copied_never_widened(self, engine, root):
        child = engine.mint_child(
            parent=root.claims,
            child_subject_id="agent:xyz",
            scopes=["read_calendar"],
            exp=root.claims.exp,
        )
        assert child.claims.max_depth == 5

    def test_approval_metadata_recorded(self, engine, root):
        child = engine.mint_child(
            parent=root.claims,
            child_subject_id="agent:xyz",
            scopes=["send_email"],
            exp=root.claims.exp,
            approval_required=True,
            approved_by="human:admin",
        )
        assert child.claims.approval_required is True
        assert child.claims.approved_by == "human:admin"


class TestDecoding:
    def test_round_trip(self, engine, root):
        decoded = engine.decode(root.token)
        assert decoded.jti == root.claims.jti
        assert decoded.scopes == root.claims.scopes

    def test_tampered_payload_rejected(self, engine, root):
        """The whole security model: an edited claim must fail the signature."""
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["scopes"] = ["spend_money"]
        forged = jwt.encode(claims, "attacker-secret", algorithm="HS256")
        with pytest.raises(TokenError) as exc:
            engine.decode(forged)
        assert exc.value.reason == REASON_INVALID_SIGNATURE

    def test_algorithm_confusion_rejected(self, engine, root):
        """An unsigned 'alg: none' token must never be accepted."""
        claims = jwt.decode(root.token, options={"verify_signature": False})
        claims["scopes"] = ["spend_money"]
        unsigned = jwt.encode(claims, key="", algorithm="none")
        with pytest.raises(TokenError):
            engine.decode(unsigned)

    def test_expired_token_reported_as_expired(self, engine):
        settings = build_settings()
        claims = TokenClaims(
            jti="j",
            sub="human:abc",
            iss=settings.issuer,
            issued_for="human:abc",
            scopes=["a"],
            depth=0,
            max_depth=5,
            iat=utcnow_ts() - 100,
            exp=utcnow_ts() - 10,
            root_jti="j",
        )
        token = jwt.encode(
            claims.model_dump(mode="json"), settings.jwt_secret, algorithm="HS256"
        )
        with pytest.raises(TokenError) as exc:
            engine.decode(token)
        assert exc.value.reason == REASON_EXPIRED

    def test_expiry_check_can_be_deferred(self, engine):
        """verify() needs the claims of an expired token to audit the denial."""
        settings = build_settings()
        claims = TokenClaims(
            jti="j",
            sub="human:abc",
            iss=settings.issuer,
            issued_for="human:abc",
            scopes=["a"],
            depth=0,
            max_depth=5,
            iat=utcnow_ts() - 100,
            exp=utcnow_ts() - 10,
            root_jti="j",
        )
        token = jwt.encode(
            claims.model_dump(mode="json"), settings.jwt_secret, algorithm="HS256"
        )
        decoded = engine.decode(token, verify_exp=False)
        assert decoded.jti == "j"

    def test_foreign_issuer_rejected(self, engine):
        settings = build_settings()
        token = jwt.encode(
            {
                "jti": "j",
                "sub": "human:abc",
                "iss": "some-other-service",
                "issued_for": "human:abc",
                "scopes": ["a"],
                "delegation_chain": [],
                "depth": 0,
                "max_depth": 5,
                "iat": utcnow_ts(),
                "exp": utcnow_ts() + 60,
                "root_jti": "j",
            },
            settings.jwt_secret,
            algorithm="HS256",
        )
        with pytest.raises(TokenError) as exc:
            engine.decode(token)
        assert exc.value.reason == REASON_MALFORMED

    def test_missing_required_claim_rejected(self, engine):
        settings = build_settings()
        token = jwt.encode(
            {"sub": "human:abc", "iss": settings.issuer}, settings.jwt_secret, algorithm="HS256"
        )
        with pytest.raises(TokenError) as exc:
            engine.decode(token)
        assert exc.value.reason == REASON_MALFORMED

    def test_garbage_string_rejected(self, engine):
        with pytest.raises(TokenError) as exc:
            engine.decode("this-is-not-a-jwt")
        assert exc.value.reason == REASON_INVALID_SIGNATURE

    def test_extra_claims_rejected(self, engine):
        """The claim schema is closed, so an injected claim cannot ride along."""
        settings = build_settings()
        payload = {
            "jti": "j",
            "sub": "human:abc",
            "iss": settings.issuer,
            "issued_for": "human:abc",
            "scopes": ["a"],
            "delegation_chain": [],
            "depth": 0,
            "max_depth": 5,
            "iat": utcnow_ts(),
            "exp": utcnow_ts() + 60,
            "root_jti": "j",
            "is_admin": True,
        }
        token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
        with pytest.raises(TokenError) as exc:
            engine.decode(token)
        assert exc.value.reason == REASON_MALFORMED


class TestSecretIsolation:
    def test_token_from_another_deployment_is_rejected(self, root):
        """A token signed with a different secret must not verify here."""
        other = TokenEngine(
            build_settings(jwt_secret="a-completely-different-secret-0123456789ab")
        )
        with pytest.raises(TokenError):
            other.decode(root.token)
