"""Diagnose which Upstash Redis URL scheme actually works.

Upstash terminates plain TCP connections that do not negotiate TLS, which
surfaces as "Connection closed by server" rather than a TLS error -- so the
failure mode does not point at its own cause. This tries both schemes and
reports which one the endpoint accepts.

    .\.venv\Scripts\python.exe scripts\probe_redis_scheme.py
"""

from __future__ import annotations

import pathlib
import sys

import redis as redis_lib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in (REPO_ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def try_url(label: str, url: str) -> bool:
    display = url
    if "@" in url:
        head, _, tail = url.partition("://")
        creds, _, host = tail.partition("@")
        display = f"{head}://{creds.split(':', 1)[0]}:***@{host}"
    print(f"\n--- {label} ---")
    print(f"url: {display}")
    try:
        client = redis_lib.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=10, socket_timeout=10
        )
        print(f"ping -> {client.ping()}")
        client.set("adf:_scheme_probe", "ok", ex=20)
        value = client.get("adf:_scheme_probe")
        client.delete("adf:_scheme_probe")
        print(f"set/get round trip -> {value}")
        print("RESULT: WORKS")
        return True
    except Exception as exc:
        print(f"RESULT: FAILED -- {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    env = load_env()
    original = env.get("ADF_REDIS_URL", "")
    if not original:
        print("ADF_REDIS_URL missing from .env")
        return 1

    plain = original.replace("rediss://", "redis://", 1)
    tls = original.replace("redis://", "rediss://", 1) if not original.startswith("rediss://") else original

    plain_ok = try_url("plain TCP (redis://)", plain)
    tls_ok = try_url("TLS (rediss://)", tls)

    print("\n" + "=" * 70)
    if tls_ok and not plain_ok:
        print("Upstash requires TLS. Use the rediss:// form in .env:")
        print("  ADF_REDIS_URL=" + tls.replace(tls.split("://")[1].split("@")[0], "default:<password>"))
    elif plain_ok and not tls_ok:
        print("Endpoint accepts plain TCP only; keep redis:// in .env.")
    elif plain_ok and tls_ok:
        print("Both work. Prefer rediss:// -- the password crosses the wire either way,")
        print("and without TLS it crosses in cleartext.")
    else:
        print("Neither scheme connected. Check the endpoint/password, and whether the")
        print("database was deleted or is paused in the Upstash console.")
    return 0 if (plain_ok or tls_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
