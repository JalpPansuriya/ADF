#!/bin/sh
# Apply migrations, then hand off to the CMD.
#
# Waits for Postgres explicitly rather than relying solely on compose
# healthchecks, because `pg_isready` can pass a moment before the database
# accepts application connections.
set -e

echo "[entrypoint] waiting for the database..."
python - <<'PY'
import os
import sys
import time

import sqlalchemy

url = os.environ.get("ADF_DATABASE_URL", "")
if not url or url.startswith("sqlite"):
    sys.exit(0)

engine = sqlalchemy.create_engine(url, pool_pre_ping=True)
deadline = time.time() + 60
last_error = None
while time.time() < deadline:
    try:
        with engine.connect() as connection:
            connection.execute(sqlalchemy.text("SELECT 1"))
        print("[entrypoint] database is accepting connections")
        sys.exit(0)
    except Exception as exc:
        last_error = exc
        time.sleep(1)
print(f"[entrypoint] database never became ready: {last_error}", file=sys.stderr)
sys.exit(1)
PY

echo "[entrypoint] applying migrations..."
alembic upgrade head

echo "[entrypoint] starting: $*"
exec "$@"
