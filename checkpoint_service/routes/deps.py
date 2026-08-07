"""Shared FastAPI dependencies: container access, DB session, admin auth."""

from __future__ import annotations

import secrets

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from checkpoint_service.container import AppContainer
from checkpoint_service.db.session import session_scope


def get_container(request: Request) -> AppContainer:
    container = getattr(request.app.state, "container", None)
    if container is None:  # pragma: no cover - misconfiguration
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="service not initialised",
        )
    return container


def get_db():
    with session_scope() as session:
        yield session


def require_admin(
    container: AppContainer = Depends(get_container),
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
) -> str:
    """Static-API-key admin auth (PRD Section 15).

    ``compare_digest`` avoids leaking the key's prefix through response-time
    differences. A plain ``==`` on a secret is a timing side channel.
    """
    expected = container.settings.admin_api_key
    if not x_admin_key or not secrets.compare_digest(x_admin_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-Admin-Key",
        )
    return "human:admin"


def bearer_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> str:
    """Extract the agent's own capability token from the Authorization header."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="empty bearer token",
        )
    return token


__all__ = ["get_container", "get_db", "require_admin", "bearer_token", "Session"]
