"""Alembic environment.

The database URL comes from ``ADF_DATABASE_URL`` rather than alembic.ini so that
migrations always target the same database the service will use -- a mismatch
between the two is a classic source of "the table exists but the app says it
doesn't".
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checkpoint_service.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _resolve_database_url() -> str:
    """Resolve the target database the same way the service does.

    Precedence: an explicit ``ADF_DATABASE_URL`` in the process environment, then
    ``.env``, then the local-development default.

    The ``.env`` step matters. The service reads ``.env`` through
    pydantic-settings, but Alembic is a separate entrypoint with no such
    machinery -- so reading only ``os.getenv`` made ``alembic upgrade head``
    silently target ``localhost:5432`` while the app talked to Supabase. A
    migration tool that quietly points at a different database than the
    application is worse than one that fails, because it "succeeds" against the
    wrong server.
    """
    from_env = os.getenv("ADF_DATABASE_URL")
    if from_env:
        return from_env

    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            if key.strip() == "ADF_DATABASE_URL":
                value = value.strip().strip('"').strip("'")
                if value:
                    return value

    return "postgresql+psycopg://adf:adf@localhost:5432/adf"


database_url = _resolve_database_url()

# NOTE: the URL is deliberately NOT written back via
# ``config.set_main_option("sqlalchemy.url", ...)``. alembic.ini is parsed by
# configparser with interpolation enabled, which treats '%' as a token -- and a
# percent-encoded password (e.g. '%40' for '@', '%24' for '$') then raises
# "invalid interpolation syntax". Since URL-encoded credentials are the norm for
# hosted Postgres, the URL is passed directly to the engine instead and
# ``sqlalchemy.url`` in alembic.ini is left empty.


def _redacted(url: str) -> str:
    """Log the target without printing the password into CI output."""
    if "://" not in url or "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    creds, _, host = rest.partition("@")
    user = creds.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"


print(f"[alembic] target database: {_redacted(database_url)}")

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # create_engine rather than engine_from_config: the latter reads the URL back
    # out of the configparser section, which re-introduces the '%' interpolation
    # problem with percent-encoded passwords.
    connectable = create_engine(
        database_url,
        poolclass=pool.NullPool,
        # Supabase's pooler on port 6543 runs in transaction mode, which does not
        # keep prepared statements across transactions. Disabling the client-side
        # cache avoids "prepared statement already exists" on retried DDL.
        connect_args={"prepare_threshold": None, "connect_timeout": 30},
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, compare_type=True
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
