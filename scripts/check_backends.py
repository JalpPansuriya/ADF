"""Connectivity + schema probe for the live Supabase/Upstash backends.

Run before and after migrations to confirm what actually exists remotely.

    .\.venv\Scripts\python.exe scripts\check_backends.py
"""

from __future__ import annotations

import pathlib
import sys

import redis as redis_lib
import sqlalchemy

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

EXPECTED_TABLES = {
    "alembic_version",
    "audit_log",
    "delegation_edge",
    "pending_approval",
    "revocation",
    "subject_map",
    "token_record",
}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    path = REPO_ROOT / ".env"
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def redact(url: str) -> str:
    """Hide the password so this output is safe to paste."""
    if "@" not in url:
        return url
    scheme_sep = url.find("://")
    head = url[: scheme_sep + 3]
    rest = url[scheme_sep + 3 :]
    creds, _, host = rest.partition("@")
    user = creds.split(":", 1)[0]
    return f"{head}{user}:***@{host}"


def check_postgres(url: str) -> int:
    print("=" * 70)
    print("POSTGRES (Supabase)")
    print("=" * 70)
    print(f"url: {redact(url)}")
    try:
        engine = sqlalchemy.create_engine(
            url, pool_pre_ping=True, connect_args={"connect_timeout": 15}
        )
        with engine.connect() as conn:
            version = conn.execute(sqlalchemy.text("select version()")).scalar()
            print(f"connected OK\n  {str(version)[:80]}")
            rows = conn.execute(
                sqlalchemy.text(
                    "select table_name from information_schema.tables "
                    "where table_schema = 'public' order by table_name"
                )
            ).fetchall()
            tables = {r[0] for r in rows}
            print(f"  public tables ({len(tables)}): {sorted(tables) or '(none)'}")

            missing = EXPECTED_TABLES - tables
            extra = tables - EXPECTED_TABLES
            if missing:
                print(f"  MISSING (run alembic upgrade head): {sorted(missing)}")
            if extra:
                print(f"  unrelated tables present: {sorted(extra)}")
            if not missing:
                print("  schema complete")
                for table in ("token_record", "audit_log", "revocation"):
                    count = conn.execute(
                        sqlalchemy.text(f"select count(*) from {table}")
                    ).scalar()
                    print(f"    {table}: {count} row(s)")
        return 0
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return 1


def check_redis(url: str) -> int:
    print()
    print("=" * 70)
    print("REDIS (Upstash)")
    print("=" * 70)
    print(f"url: {redact(url)}")
    try:
        client = redis_lib.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=10, socket_timeout=10
        )
        print(f"ping: {client.ping()}")
        info_keys = ("redis_version", "maxmemory_human")
        try:
            info = client.info()
            for key in info_keys:
                if key in info:
                    print(f"  {key}: {info[key]}")
        except Exception as exc:
            # Upstash restricts INFO on some plans; not fatal.
            print(f"  (INFO unavailable: {exc})")

        # Round-trip the exact operations the revocation store relies on.
        client.set("adf:_probe", "1", ex=30)
        assert client.get("adf:_probe") == "1"
        client.sadd("adf:_probe_set", "a", "b")
        assert client.sismember("adf:_probe_set", "a")
        assert not client.sismember("adf:_probe_set", "zzz")
        client.zadd("adf:_probe_z", {"m": 1.0})
        assert client.zcard("adf:_probe_z") == 1
        pipe = client.pipeline()
        pipe.sadd("adf:_probe_set", "c")
        pipe.scard("adf:_probe_set")
        assert pipe.execute()[1] == 3
        client.delete("adf:_probe", "adf:_probe_set", "adf:_probe_z")
        print("  SET/GET, SADD/SISMEMBER, ZADD/ZCARD, pipeline: all OK")

        ready = client.get("adf:cache_ready")
        revoked = client.scard("adf:revoked") if ready else 0
        print(f"  cache_ready sentinel: {ready!r}, revoked entries: {revoked}")
        return 0
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return 1


def main() -> int:
    env = load_env()
    db_url = env.get("ADF_DATABASE_URL", "")
    redis_url = env.get("ADF_REDIS_URL", "")
    if not db_url or not redis_url:
        print("ADF_DATABASE_URL or ADF_REDIS_URL missing from .env")
        return 1
    failures = check_postgres(db_url) + check_redis(redis_url)
    print()
    print("RESULT:", "both backends reachable" if failures == 0 else "see failures above")
    return failures


if __name__ == "__main__":
    sys.exit(main())
