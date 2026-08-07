"""Token Engine -- mint, sign and decode capability tokens via PyJWT.

Signing is HS256 for v1 (PRD Section 9). The upgrade path to RS256 is a
two-line change here plus key distribution; see the README. HS256 means every
verifier needs the signing secret, which is why verification is centralised in
this service rather than pushed to callers.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTokenError,
)

from checkpoint_service.config import Settings
from checkpoint_service.models.token import DelegationChainEntry, TokenClaims
from checkpoint_service.utils import iso, utcnow, utcnow_ts

# Reasons surfaced to callers. Deliberately coarse: a caller learns *that* a
# token is unusable, not the internal detail of why the signature failed.
REASON_EXPIRED = "expired"
REASON_REVOKED = "revoked"
REASON_INVALID_SIGNATURE = "invalid_signature"
REASON_SCOPE_NOT_GRANTED = "scope_not_granted"
REASON_CIRCUIT_OPEN = "circuit_open"
REASON_MALFORMED = "malformed_token"


class TokenError(Exception):
    """Token could not be decoded or failed a cryptographic check."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class MintedToken:
    """A freshly signed token plus its decoded claims."""

    token: str
    claims: TokenClaims

    @property
    def jti(self) -> str:
        return self.claims.jti

    @property
    def expires_at_iso(self) -> str:
        return iso(self.claims.expires_at)


class TokenEngine:
    """Stateless JWT mint/decode. Holds no revocation or policy knowledge."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

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
    ) -> MintedToken:
        """Mint a depth-0 root token authorised directly by a human."""
        jti = str(uuid.uuid4())
        now = utcnow_ts()
        claims = TokenClaims(
            jti=jti,
            sub=subject_id,
            iss=self._settings.issuer,
            issued_for=subject_id,  # a root token authorises itself
            scopes=sorted(set(scopes)),
            delegation_chain=[],
            depth=0,
            max_depth=max_depth,
            iat=now,
            exp=now + ttl_seconds,
            approval_required=False,
            approved_by=None,
            root_jti=jti,
        )
        return MintedToken(token=self._encode(claims), claims=claims)

    def mint_child(
        self,
        *,
        parent: TokenClaims,
        child_subject_id: str,
        scopes: list[str],
        exp: int,
        approval_required: bool = False,
        approved_by: str | None = None,
    ) -> MintedToken:
        """Mint a delegated token.

        Assumes the Delegation Engine has already validated the subset, depth
        and expiry rules. ``exp`` is passed in pre-clamped rather than recomputed
        here so there is exactly one place that decides expiry.
        """
        now = utcnow_ts()
        chain = [*parent.delegation_chain, self.chain_entry_for(parent)]
        claims = TokenClaims(
            jti=str(uuid.uuid4()),
            sub=child_subject_id,
            iss=self._settings.issuer,
            issued_for=f"agent:{parent.jti}",
            scopes=sorted(set(scopes)),
            delegation_chain=chain,
            depth=parent.depth + 1,
            max_depth=parent.max_depth,
            iat=now,
            exp=exp,
            approval_required=approval_required,
            approved_by=approved_by,
            root_jti=parent.root_jti,
        )
        return MintedToken(token=self._encode(claims), claims=claims)

    @staticmethod
    def chain_entry_for(claims: TokenClaims) -> DelegationChainEntry:
        """The chain entry representing this token as a granting party."""
        return DelegationChainEntry(
            agent_id=claims.sub,
            jti=claims.jti,
            scopes=sorted(set(claims.scopes)),
            ts=iso(utcnow()),
        )

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------
    def decode(self, token: str, *, verify_exp: bool = True) -> TokenClaims:
        """Verify signature and issuer, then return typed claims.

        Raises :class:`TokenError` with ``reason`` in {invalid_signature,
        expired, malformed_token}. Signature verification always happens before
        any claim is read -- see :meth:`decode_unverified` for the one narrow
        exception and why it is not used on the enforcement path.
        """
        try:
            payload = jwt.decode(
                token,
                self._settings.jwt_secret,
                algorithms=[self._settings.jwt_algorithm],
                issuer=self._settings.issuer,
                options={"verify_exp": verify_exp, "require": ["jti", "sub", "exp", "iat"]},
            )
        except ExpiredSignatureError as exc:
            raise TokenError(REASON_EXPIRED, str(exc)) from exc
        except (InvalidSignatureError, DecodeError) as exc:
            raise TokenError(REASON_INVALID_SIGNATURE, str(exc)) from exc
        except InvalidTokenError as exc:
            # Covers bad issuer, missing required claims, malformed structure.
            raise TokenError(REASON_MALFORMED, str(exc)) from exc

        try:
            return TokenClaims.model_validate(payload)
        except Exception as exc:  # claim set does not match our schema
            raise TokenError(REASON_MALFORMED, str(exc)) from exc

    def decode_unverified(self, token: str) -> dict:
        """Decode WITHOUT signature verification.

        Only for diagnostics and dashboard rendering of already-persisted rows.
        Never call this on the enforcement path: an attacker controls every byte
        of an unverified payload.
        """
        return jwt.decode(token, options={"verify_signature": False})

    # ------------------------------------------------------------------
    def _encode(self, claims: TokenClaims) -> str:
        return jwt.encode(
            claims.model_dump(mode="json"),
            self._settings.jwt_secret,
            algorithm=self._settings.jwt_algorithm,
        )
