"""``/api/v1/audit/*`` endpoints: chain lineage, log query, integrity, tree view."""

from __future__ import annotations

import datetime as _dt

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from checkpoint_service.container import AppContainer
from checkpoint_service.models.audit import AuditLog, PendingApproval, TokenRecord
from checkpoint_service.models.token import ChainEntryOut, ChainResponse, IntegrityResponse
from checkpoint_service.routes.deps import get_container, get_db
from checkpoint_service.utils import as_utc, iso, utcnow

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/chain/{jti}", response_model=ChainResponse)
def chain(
    jti: str,
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
) -> ChainResponse:
    """Full root-to-leaf lineage for a token.

    Rebuilt by walking ``token_record.parent_jti`` server-side rather than reading
    the JWT's ``delegation_chain`` claim, so a caller cannot present a fabricated
    lineage. The signed claim and this reconstruction are cross-checked by
    ``tests/test_audit_chain.py``.
    """
    leaf = session.get(TokenRecord, jti)
    if leaf is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown jti")

    lineage: list[TokenRecord] = []
    cursor: TokenRecord | None = leaf
    seen: set[str] = set()
    while cursor is not None and cursor.jti not in seen:
        seen.add(cursor.jti)
        lineage.append(cursor)
        cursor = (
            session.get(TokenRecord, cursor.parent_jti) if cursor.parent_jti else None
        )
    lineage.reverse()

    revoked = container.revocation.revoked_among(session, [r.jti for r in lineage])
    labels = container.subjects.labels_for(session, [r.subject_id for r in lineage])
    now = utcnow()

    entries = [
        ChainEntryOut(
            agent_id=record.subject_id,
            display_label=labels.get(record.subject_id),
            jti=record.jti,
            scopes=list(record.scopes),
            ts=iso(record.issued_at),
            depth=record.depth,
            revoked=record.jti in revoked,
            expired=as_utc(record.expires_at) < now,
        )
        for record in lineage
    ]
    return ChainResponse(
        jti=jti,
        depth=leaf.depth,
        chain=entries,
        scopes=list(leaf.scopes),
        revoked=leaf.jti in revoked,
        expired=as_utc(leaf.expires_at) < now,
    )


@router.get("/log")
def log(
    session: Session = Depends(get_db),
    agent_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    since: _dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Paginated audit log query for the dashboard (PRD 6.7)."""
    stmt = select(AuditLog)
    if agent_id:
        stmt = stmt.where(AuditLog.actor_id == agent_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if decision:
        stmt = stmt.where(AuditLog.decision == decision)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)

    total = len(session.scalars(stmt).all())
    rows = session.scalars(
        stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    ).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [
            {
                "id": row.id,
                "ts": row.event_ts,
                "action": row.action,
                "actor_id": row.actor_id,
                "jti": row.jti,
                "parent_jti": row.parent_jti,
                "root_jti": row.root_jti,
                "scopes": row.scopes,
                "denied_scopes": row.denied_scopes,
                "required_scope": row.required_scope,
                "decision": row.decision,
                "reason": row.reason,
                "depth": row.depth,
                "detail": row.detail,
                "latency_ms": row.latency_ms,
                "row_hash": row.row_hash,
                "prev_hash": row.prev_hash,
            }
            for row in rows
        ],
    }


@router.get("/verify_integrity", response_model=IntegrityResponse)
def verify_integrity(
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
) -> IntegrityResponse:
    """Walk the hash chain and report the first broken link (PRD 8.5).

    Flushes the buffer first so a pending verify_success event is not mistaken
    for a gap in the chain.
    """
    container.audit.flush()
    intact, rows_checked, first_broken, detail = container.audit.verify_integrity(session)
    return IntegrityResponse(
        intact=intact,
        rows_checked=rows_checked,
        first_broken_row_id=first_broken,
        detail=detail,
    )


@router.get("/tree")
def tree(
    container: AppContainer = Depends(get_container),
    session: Session = Depends(get_db),
    root_jti: str | None = Query(default=None),
) -> dict:
    """Delegation forest for the dashboard's live tree view."""
    stmt = select(TokenRecord)
    if root_jti:
        stmt = stmt.where(TokenRecord.root_jti == root_jti)
    records = session.scalars(stmt.order_by(TokenRecord.depth.asc())).all()

    revoked = container.revocation.revoked_among(session, [r.jti for r in records])
    labels = container.subjects.labels_for(session, [r.subject_id for r in records])
    now = utcnow()

    nodes: dict[str, dict] = {}
    for record in records:
        nodes[record.jti] = {
            "jti": record.jti,
            "subject_id": record.subject_id,
            "label": labels.get(record.subject_id, record.subject_id),
            "parent_jti": record.parent_jti,
            "root_jti": record.root_jti,
            "depth": record.depth,
            "max_depth": record.max_depth,
            "scopes": list(record.scopes),
            "issued_at": iso(record.issued_at),
            "expires_at": iso(record.expires_at),
            "revoked": record.jti in revoked,
            "expired": as_utc(record.expires_at) < now,
            "approval_required": record.approval_required,
            "approved_by": record.approved_by,
            "children": [],
        }

    roots: list[dict] = []
    for node in nodes.values():
        parent = nodes.get(node["parent_jti"]) if node["parent_jti"] else None
        if parent is not None:
            parent["children"].append(node)
        else:
            roots.append(node)
    return {"roots": roots, "node_count": len(nodes)}


@router.get("/approvals")
def approvals(
    session: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
) -> dict:
    """Approvals queue for the dashboard."""
    stmt = select(PendingApproval)
    if status_filter:
        stmt = stmt.where(PendingApproval.status == status_filter)
    rows = session.scalars(stmt.order_by(PendingApproval.created_at.desc())).all()
    return {
        "total": len(rows),
        "approvals": [
            {
                "approval_id": row.approval_id,
                "parent_jti": row.parent_jti,
                "parent_subject_id": row.parent_subject_id,
                "child_agent_id": row.child_agent_id,
                "requested_scopes": list(row.requested_scopes),
                "sensitive_scopes": list(row.sensitive_scopes),
                "status": row.status,
                "created_at": iso(row.created_at),
                "expires_at": iso(row.expires_at),
                "decided_at": iso(row.decided_at) if row.decided_at else None,
                "approved_by": row.approved_by,
                "child_jti": row.child_jti,
            }
            for row in rows
        ],
    }
