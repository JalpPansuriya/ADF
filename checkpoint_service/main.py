"""FastAPI application entrypoint for the Checkpoint Service."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from checkpoint_service import __version__
from checkpoint_service.config import ConfigurationError, get_settings
from checkpoint_service.container import AppContainer
from checkpoint_service.routes import admin, audit, tokens

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

API_PREFIX = "/api/v1"

DESCRIPTION = """
Authorization and capability-narrowing for multi-agent AI pipelines.

Every delegation is forced to be a **strict subset** of the parent's permissions,
every hop is recorded in a tamper-evident hash-chained audit log, and revoking any
token instantly invalidates its entire downstream subtree.

Security notes for API consumers:
* `POST /tokens/root`, `/tokens/revoke`, `/tokens/approve`, `/tokens/deny` and all
  `/admin/*` routes require the `X-Admin-Key` header.
* `POST /tokens/delegate` authenticates with the calling agent's own capability
  token as a bearer credential.
* `POST /tokens/verify` is the enforcement checkpoint and is intentionally open to
  any caller holding a token -- it reveals nothing a token holder does not already
  have.
"""


def create_app(container: AppContainer | None = None) -> FastAPI:
    """Build the ASGI app.

    A pre-built ``container`` may be injected by tests; otherwise one is created
    from validated settings at startup.

    Secret validation happens in ``lifespan``, not here. Importing this module
    must not require a populated ``.env`` -- otherwise the static import check
    (`python -c "import checkpoint_service.main"`) and OpenAPI schema generation
    would both demand production secrets. The service still refuses to *serve*
    without them.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if container is None:
            settings = get_settings()  # raises ConfigurationError if unsafe
            app.state.container = AppContainer(settings, create_tables=True)
        else:
            app.state.container = container
        await app.state.container.startup()
        logger.info("Checkpoint Service ready (v%s)", __version__)
        try:
            yield
        finally:
            await app.state.container.shutdown()

    if container is not None:
        cors_origins = container.settings.cors_origins
    else:
        try:
            cors_origins = get_settings().cors_origins
        except ConfigurationError:
            # Import-time only. Startup will re-raise this before serving traffic.
            cors_origins = []

    app = FastAPI(
        title="Agent Delegation Firewall -- Checkpoint Service",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Admin-Key"],
    )

    app.include_router(tokens.router, prefix=API_PREFIX)
    app.include_router(audit.router, prefix=API_PREFIX)
    app.include_router(admin.router, prefix=API_PREFIX)
    # /health is also exposed unprefixed for container health checks.
    app.include_router(admin.router)

    return app


app = create_app()
