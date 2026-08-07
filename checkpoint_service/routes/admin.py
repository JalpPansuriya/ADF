"""``/api/v1/admin/*`` endpoints and the unauthenticated ``/health`` probe."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from checkpoint_service.container import AppContainer
from checkpoint_service.db import redis_client
from checkpoint_service.engine.audit_logger import AuditEvent
from checkpoint_service.models.audit import AuditLog, PendingApproval, Revocation, TokenRecord
from checkpoint_service.routes.deps import get_container, get_db, require_admin

router = APIRouter(tags=["admin"])


@router.get("/health")
def health(
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
) -> dict:
    """Circuit breaker + system status (PRD 6.8/8.3).

    Deliberately unauthenticated so orchestrators can probe it, and deliberately
    free of secrets or token material. It does expose breaker state and aggregate
    counts, which is operational metadata rather than capability data.
    """
    state = container.circuit.state()
    counts = {
        "tokens": session.scalar(select(func.count()).select_from(TokenRecord)) or 0,
        "revocations": session.scalar(select(func.count()).select_from(Revocation)) or 0,
        "audit_rows": session.scalar(select(func.count()).select_from(AuditLog)) or 0,
        "pending_approvals": session.scalar(
            select(func.count())
            .select_from(PendingApproval)
            .where(PendingApproval.status == "pending")
        )
        or 0,
    }
    return {
        "status": "degraded" if state.open else "ok",
        "circuit": {
            "open": state.open,
            "reason": state.reason,
            "error_rate": round(state.error_rate, 4),
            "samples": state.samples,
            "errors": state.errors,
            "window_seconds": container.settings.circuit_window_seconds,
            "threshold": container.settings.circuit_error_rate_threshold,
            "min_samples": container.settings.circuit_min_samples,
        },
        "redis": {
            "available": redis_client.redis_available(),
            "note": (
                "cache only; revocation truth lives in Postgres, so a Redis outage "
                "degrades latency, not correctness"
            ),
        },
        "rate_limits": {
            "delegate_per_min": container.settings.rate_limit_delegate_per_min,
            "verify_per_min": container.settings.rate_limit_verify_per_min,
            "current_windows": container.rate_limiter.snapshot(),
            "exempt_agents": container.settings.guardrail_exempt_agents,
        },
        "counts": counts,
        "sensitive_scopes": sorted(container.settings.sensitive_scopes),
        "max_delegation_depth": container.settings.max_delegation_depth,
    }


@router.post("/admin/circuit/reset")
def reset_circuit(
    container: AppContainer = Depends(get_container),
    admin: str = Depends(require_admin),
) -> dict:
    """Break glass: manually close the circuit breaker (PRD 8.3).

    Requires the admin key. There is no automatic recovery by design -- an
    authorization service that silently re-closes hides the incident that opened
    it and can flap while the underlying fault persists.
    """
    previous = container.circuit.state()
    container.circuit.reset()
    container.audit.log(
        AuditEvent(
            action="circuit_reset",
            actor_id=admin,
            decision="allow",
            reason="break glass: manual circuit breaker reset",
            detail={"previous_reason": previous.reason, "was_open": previous.open},
        )
    )
    return {"circuit_open": False, "was_open": previous.open, "reset_by": admin}


@router.post("/admin/audit/flush")
def flush_audit(
    container: AppContainer = Depends(get_container),
    _admin: str = Depends(require_admin),
) -> dict:
    """Force-flush the buffered audit writer.

    Exists so an operator (or the eval harness) can make buffered verify_success
    rows durable on demand before running an integrity check.
    """
    written = container.audit.flush()
    return {"flushed": written}


@router.get("/admin/subjects")
def list_subjects(
    session: Session = Depends(get_db),
    _admin: str = Depends(require_admin),
) -> dict:
    """Opaque-subject -> display-label mapping (PRD 8.6).

    Admin-gated because it is the only place the pseudonymisation can be
    reversed.
    """
    from checkpoint_service.models.audit import SubjectMap

    rows = session.scalars(select(SubjectMap)).all()
    return {
        "total": len(rows),
        "subjects": [
            {
                "subject_id": row.subject_id,
                "kind": row.kind,
                "display_label": row.display_label,
                "identifier_hash": row.identifier_hash,
            }
            for row in rows
        ],
    }
