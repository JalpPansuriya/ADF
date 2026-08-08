"""Mint, sign and decode capability tokens.

Stateless by design: this class holds no revocation state and no policy. It knows
how to turn claims into a signed string and back, nothing more. Everything that
can say "no" lives in :mod:`agperms.firewall`.

Signing is HMAC (HS256 by default), which means every verifier needs the secret.
That is fine for in-process embedding -- the case this library is built for -- and
is why a distributed deployment should put verification behind one service rather
than sharing the key around.
"""

from __future__ import annotations

import uuid

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTokenError,
)

from agperms._time import iso, utcnow, utcnow_ts
from agperms.config import Config
from agperms.errors import (
    REASON_EXPIRED,
    REASON_INVALID_SIGNATURE,
    REASON_MALFORMED,
    TokenError,
)
from agperms.models import Capability, DelegationChainEntry, TokenClaims


class TokenEngine:
    """Turns claims into signed tokens and back. No policy, no state."""

    def __init__(self, config: Config) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Minting
    # ------------------------------------------------------------------
    def mint_root(
        self,
        *,
        subject_id: str,
        scopes: list[str],
        ttl_seconds: int,
        max_depth: int,
    ) -> Capability:
        """Mint a depth-0 capability, authorised directly by a human."""
        jti = str(uuid.uuid4())
        now = utcnow_ts()
        claims = TokenClaims(
            jti=jti,
            sub=subject_id,
            iss=self._config.issuer,
            issued_for=subject_id,  # a root authorises itself
            scopes=tuple(sorted(set(scopes))),
            delegation_chain=(),
            depth=0,
            max_depth=max_depth,
            iat=now,
            exp=now + ttl_seconds,
            approval_required=False,
            approved_by=None,
            root_jti=jti,  # a root is its own chain terminus
        )
        return Capability(token=self._encode(claims), claims=claims)

    def mint_child(
        self,
        *,
        parent: TokenClaims,
        child_subject_id: str,
        scopes: list[str],
        exp: int,
        approval_required: bool = False,
        approved_by: str | None = None,
    ) -> Capability:
        """Mint a delegated capability.

        Assumes the subset, depth and expiry rules have already been checked.
        ``exp`` arrives pre-clamped rather than being recomputed here, so exactly
        one place in the codebase decides how long a child may live.
        """
        now = utcnow_ts()
        chain = (*parent.delegation_chain, self.chain_entry_for(parent))
        claims = TokenClaims(
            jti=str(uuid.uuid4()),
            sub=child_subject_id,
            iss=self._config.issuer,
            issued_for=f"agent:{parent.jti}",
            scopes=tuple(sorted(set(scopes))),
            delegation_chain=chain,
            depth=parent.depth + 1,
            max_depth=parent.max_depth,  # copied verbatim; a child cannot widen it
            iat=now,
            exp=exp,
            approval_required=approval_required,
            approved_by=approved_by,
            root_jti=parent.root_jti,
        )
        return Capability(token=self._encode(claims), claims=claims)

    @staticmethod
    def chain_entry_for(claims: TokenClaims) -> DelegationChainEntry:
        """The chain entry recording this token as a granting party."""
        return DelegationChainEntry(
            agent_id=claims.sub,
            jti=claims.jti,
            scopes=tuple(sorted(set(claims.scopes))),
            ts=iso(utcnow()),
        )

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------
    def decode(self, token: str, *, verify_exp: bool = True) -> TokenClaims:
        """Verify the signature and issuer, then return typed claims.

        Nothing in the payload is trusted before this returns. Callers that need
        to report "expired" distinctly from "forged" pass ``verify_exp=False`` and
        check expiry themselves after the signature has been established.
        """
        if not token:
            raise TokenError(REASON_MALFORMED, "empty token")
        try:
            payload = jwt.decode(
                token,
                self._config.jwt_secret,
                algorithms=[self._config.jwt_algorithm],
                issuer=self._config.issuer,
                options={
                    "verify_exp": verify_exp,
                    "require": ["jti", "sub", "exp", "iat"],
                },
            )
        except ExpiredSignatureError as exc:
            raise TokenError(REASON_EXPIRED, str(exc)) from exc
        except (InvalidSignatureError, DecodeError) as exc:
            raise TokenError(REASON_INVALID_SIGNATURE, str(exc)) from exc
        except InvalidTokenError as exc:
            # Bad issuer, missing required claim, malformed structure.
            raise TokenError(REASON_MALFORMED, str(exc)) from exc

        return TokenClaims.from_payload(payload)

    def decode_unverified(self, token: str) -> dict:
        """Decode WITHOUT verifying the signature.

        For diagnostics and rendering records you already trust. Never call this
        to make an authorization decision: every byte of an unverified payload is
        attacker-controlled.
        """
        return jwt.decode(token, options={"verify_signature": False})

    # ------------------------------------------------------------------
    def _encode(self, claims: TokenClaims) -> str:
        return jwt.encode(
            claims.to_payload(),
            self._config.jwt_secret,
            algorithm=self._config.jwt_algorithm,
        )


__all__ = ["TokenEngine"]
