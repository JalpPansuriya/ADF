"""``/api/v1/tokens/*`` endpoints (PRD Section 6)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from checkpoint_service.container import AppContainer
from checkpoint_service.engine.delegation_engine import (
    DepthLimitExceeded,
    ParentTokenInvalid,
    PendingApprovalCreated,
    RootChainBroken,
    ScopeEscalationDenied,
)
from checkpoint_service.engine.guardrails import CircuitOpen, RateLimitExceeded
from checkpoint_service.engine.token_engine import REASON_CIRCUIT_OPEN
from checkpoint_service.models.audit import PendingApproval
from checkpoint_service.models.token import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    DelegateRequest,
    DelegateResponse,
    PendingTokenResponse,
    RevokeRequest,
    RevokeResponse,
    RootTokenRequest,
    RootTokenResponse,
    VerifyRequest,
)
from checkpoint_service.routes.deps import (
    bearer_token,
    get_container,
    get_db,
    require_admin,
)
from checkpoint_service.utils import iso

router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.post("/root", status_code=status.HTTP_201_CREATED, response_model=RootTokenResponse)
def mint_root(
    payload: RootTokenRequest,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
    _admin: str = Depends(require_admin),
) -> RootTokenResponse:
    """Human-only root mint. Requires ``X-Admin-Key``."""
    minted = container.engine.mint_root(
        session,
        human_id=payload.human_id,
        scopes=payload.scopes,
        ttl_seconds=payload.ttl_seconds,
        max_depth=payload.max_depth,
    )
    return RootTokenResponse(
        token=minted.token,
        jti=minted.jti,
        subject_id=minted.claims.sub,
        scopes=minted.claims.scopes,
        max_depth=minted.claims.max_depth,
        expires_at=minted.expires_at_iso,
    )


@router.post("/delegate", status_code=status.HTTP_201_CREATED)
def delegate(
    payload: DelegateRequest,
    response: Response,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
    parent_token: str = Depends(bearer_token),
):
    """Mint a narrower child token for a sub-agent.

    Returns 201 with a token, 202 when human approval is required, 403 on scope
    escalation or depth violation, 401 when the parent token is unusable, 429 when
    rate limited, 503 when the circuit breaker is open.
    """
    try:
        result = container.engine.delegate(
            session,
            parent_token=parent_token,
            child_agent_id=payload.child_agent_id,
            requested_scopes=payload.requested_scopes,
            ttl_seconds=payload.ttl_seconds,
        )
    except CircuitOpen as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": REASON_CIRCUIT_OPEN, "message": str(exc)},
        ) from exc
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "limit": exc.limit,
                "window_seconds": exc.window_seconds,
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except ParentTokenInvalid as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "parent_token_invalid", "reason": exc.reason},
        ) from exc
    except ScopeEscalationDenied as exc:
        # Body shape is fixed by PRD 6.2 and asserted field-by-field in the tests.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "scope_escalation_denied",
                "requested": exc.requested,
                "allowed_max": exc.allowed_max,
                "denied_scopes": exc.denied,
            },
        ) from exc
    except DepthLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "depth_limit_exceeded",
                "depth": exc.depth,
                "max_depth": exc.max_depth,
            },
        ) from exc
    except RootChainBroken as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "root_chain_broken", "reason": str(exc)},
        ) from exc

    if isinstance(result, PendingApprovalCreated):
        response.status_code = status.HTTP_202_ACCEPTED
        return {
            "status": "pending_approval",
            "approval_id": result.approval_id,
            "message": (
                f"{', '.join(result.sensitive_scopes)} requires human approval"
            ),
            "requested_scopes": result.requested_scopes,
            "sensitive_scopes": result.sensitive_scopes,
            "expires_at": result.expires_at,
        }

    return DelegateResponse(
        token=result.token,
        jti=result.jti,
        subject_id=result.claims.sub,
        scopes=result.claims.scopes,
        depth=result.claims.depth,
        expires_at=result.expires_at_iso,
        approval_required=result.claims.approval_required,
        approved_by=result.claims.approved_by,
    )


@router.post("/verify")
def verify(
    payload: VerifyRequest,
    response: Response,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
):
    """The enforcement checkpoint. Called before executing any agent action."""
    try:
        outcome = container.engine.verify(
            session, token=payload.token, required_scope=payload.required_scope
        )
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "rate_limit_exceeded",
                "limit": exc.limit,
                "window_seconds": exc.window_seconds,
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    if not outcome.valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"valid": False, "reason": outcome.reason}

    claims = outcome.claims
    assert claims is not None
    return {
        "valid": True,
        "agent_id": claims.sub,
        "jti": claims.jti,
        "remaining_scopes": claims.scopes,
        "depth": claims.depth,
        "expires_at": iso(claims.expires_at),
    }


@router.post("/revoke", response_model=RevokeResponse)
def revoke(
    payload: RevokeRequest,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
    admin: str = Depends(require_admin),
) -> RevokeResponse:
    """Revoke a token and its entire downstream subtree."""
    revoked, latency_ms = container.engine.revoke(
        session, jti=payload.jti, reason=payload.reason, actor_id=admin
    )
    return RevokeResponse(
        revoked=True,
        subtree_count=len(revoked),
        revoked_jtis=revoked,
        latency_ms=round(latency_ms, 3),
    )


@router.post("/approve", response_model=ApprovalDecisionResponse)
def approve(
    payload: ApprovalDecisionRequest,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
    admin: str = Depends(require_admin),
) -> ApprovalDecisionResponse:
    """Human approves a pending sensitive delegation; the child token is minted here."""
    if payload.decision == "deny":
        return _deny(container, session, payload, admin)
    try:
        record, minted = container.engine.approve(
            session, approval_id=payload.approval_id, approver_id=admin
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ParentTokenInvalid as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "parent_token_invalid", "reason": exc.reason},
        ) from exc
    except RootChainBroken as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "root_chain_broken", "reason": str(exc)},
        ) from exc

    return ApprovalDecisionResponse(
        approval_id=record.approval_id,
        status=record.status,
        child_jti=minted.jti,
        scopes=minted.claims.scopes,
        message=(
            "approved; the delegating agent may now collect the token from "
            f"GET /api/v1/tokens/pending/{record.approval_id}"
        ),
    )


@router.post("/deny", response_model=ApprovalDecisionResponse)
def deny(
    payload: ApprovalDecisionRequest,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
    admin: str = Depends(require_admin),
) -> ApprovalDecisionResponse:
    """Human denies a pending delegation. No token is ever minted."""
    return _deny(container, session, payload, admin)


def _deny(
    container: AppContainer,
    session: Session,
    payload: ApprovalDecisionRequest,
    admin: str,
) -> ApprovalDecisionResponse:
    try:
        record = container.engine.deny(
            session, approval_id=payload.approval_id, approver_id=admin
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return ApprovalDecisionResponse(
        approval_id=record.approval_id,
        status=record.status,
        child_jti=None,
        scopes=None,
        message="denied; no token was minted",
    )


@router.get("/pending/{approval_id}", response_model=PendingTokenResponse)
def collect_pending(
    approval_id: str,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
) -> PendingTokenResponse:
    """Agent polls for the outcome of its approval request.

    Returns the JWT only once approved. Marking ``collected`` gives the dashboard
    a signal that the token reached the agent; it is intentionally not enforced as
    single-use, because a network failure between mint and receipt would otherwise
    strand the agent with no way to obtain a token it was granted.
    """
    record = session.get(PendingApproval, approval_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown approval_id")

    container.engine.expire_stale_approvals(session)
    session.refresh(record)

    if record.status == "approved" and record.child_token:
        if not record.collected:
            record.collected = True
            session.flush()
        expires_at = None
        if record.child_jti:
            from checkpoint_service.models.audit import TokenRecord

            child = session.get(TokenRecord, record.child_jti)
            if child is not None:
                expires_at = iso(child.expires_at)
        return PendingTokenResponse(
            approval_id=approval_id,
            status="approved",
            token=record.child_token,
            jti=record.child_jti,
            scopes=list(record.requested_scopes),
            expires_at=expires_at,
            message="approved; token issued",
        )

    messages = {
        "pending": "awaiting human approval",
        "denied": "a human denied this delegation; no token was minted",
        "expired": "the approval request timed out; no token was minted",
    }
    return PendingTokenResponse(
        approval_id=approval_id,
        status=record.status,
        token=None,
        jti=None,
        scopes=list(record.requested_scopes),
        expires_at=None,
        message=messages.get(record.status, record.status),
    )
