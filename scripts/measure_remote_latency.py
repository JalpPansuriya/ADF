"""Measure per-operation latency against the live remote backends.

The in-process harness reports sub-millisecond figures because SQLite and
fakeredis are in the same process. Against Supabase (ap-northeast-1) and Upstash
every database call is a network round trip, so this script measures the real
cost and attributes it: raw RTT to each backend, then whole API operations.

    .\.venv\Scripts\python.exe scripts\measure_remote_latency.py
"""

from __future__ import annotations

import json
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.request

import redis as redis_lib
import sqlalchemy

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
API = "http://127.0.0.1:8000/api/v1"


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in (REPO_ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    idx = min(int(round(p / 100 * (len(ordered) - 1))), len(ordered) - 1)
    return ordered[idx]


def summarise(label: str, samples: list[float]) -> None:
    print(
        f"  {label:<34} n={len(samples):<4} "
        f"p50={statistics.median(samples):8.2f}ms  "
        f"p95={pct(samples, 95):8.2f}ms  "
        f"max={max(samples):8.2f}ms"
    )


def post(path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    request = urllib.request.Request(
        f"{API}{path}", data=data, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            # Non-JSON error body (e.g. a proxy/gateway page or a truncated
            # response); surface it rather than masking it as a decode error.
            return exc.code, {"_raw": raw.decode("utf-8", "replace")[:400]}
    except Exception as exc:
        return 0, {"_error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    env = load_env()
    admin = {"X-Admin-Key": env["ADF_ADMIN_API_KEY"]}

    print("=" * 78)
    print("RAW BACKEND ROUND TRIPS (baseline network cost)")
    print("=" * 78)

    engine = sqlalchemy.create_engine(
        env["ADF_DATABASE_URL"],
        pool_pre_ping=False,
        connect_args={"prepare_threshold": None, "connect_timeout": 30},
    )
    with engine.connect() as conn:
        conn.execute(sqlalchemy.text("select 1"))  # warm
        samples = []
        for _ in range(20):
            t0 = time.perf_counter()
            conn.execute(sqlalchemy.text("select 1"))
            samples.append((time.perf_counter() - t0) * 1000)
        summarise("Postgres SELECT 1 (pooled conn)", samples)

    client = redis_lib.Redis.from_url(
        env["ADF_REDIS_URL"], decode_responses=True,
        socket_connect_timeout=10, socket_timeout=10,
    )
    client.ping()
    samples = []
    for _ in range(20):
        t0 = time.perf_counter()
        client.ping()
        samples.append((time.perf_counter() - t0) * 1000)
    summarise("Redis PING", samples)

    samples = []
    for _ in range(20):
        t0 = time.perf_counter()
        client.sismember("adf:revoked", "no-such-jti")
        samples.append((time.perf_counter() - t0) * 1000)
    summarise("Redis SISMEMBER (revocation read)", samples)

    print()
    print("=" * 78)
    print("API OPERATIONS (what an agent actually experiences)")
    print("=" * 78)

    status, root = post(
        "/tokens/root",
        {"human_id": "latency-probe", "scopes": ["read_calendar", "read_email"],
         "ttl_seconds": 1800},
        admin,
    )
    if status != 201:
        print(f"could not mint root token: {status} {root}")
        return 1

    # /verify is the hot path -- the number that matters most.
    samples = []
    for _ in range(5):
        post("/tokens/verify", {"token": root["token"], "required_scope": "read_calendar"})
    for _ in range(40):
        t0 = time.perf_counter()
        code, _ = post(
            "/tokens/verify", {"token": root["token"], "required_scope": "read_calendar"}
        )
        samples.append((time.perf_counter() - t0) * 1000)
        assert code == 200, code
    summarise("POST /tokens/verify (allow)", samples)

    samples = []
    for _ in range(20):
        t0 = time.perf_counter()
        code, _ = post(
            "/tokens/verify", {"token": root["token"], "required_scope": "web_search"}
        )
        samples.append((time.perf_counter() - t0) * 1000)
        assert code == 401, code
    summarise("POST /tokens/verify (deny: scope)", samples)

    # Those 20 deliberate denials push the rolling error rate past the 25%
    # threshold, so the breaker opens and every later measurement returns 503.
    # That is the guardrail working correctly -- this script is behaving like a
    # hostile client -- so reset it before measuring the write paths.
    code, body = post("/admin/circuit/reset", {}, admin)
    print(f"  [breaker reset after denial burst: {code} {body.get('was_open')}]")

    # Delegation writes to Postgres, so it is inherently slower than verify.
    children: list[dict] = []
    samples = []
    for i in range(10):
        t0 = time.perf_counter()
        code, body = post(
            "/tokens/delegate",
            {"child_agent_id": f"probe-child-{i}", "requested_scopes": ["read_calendar"],
             "ttl_seconds": 600},
            {"Authorization": f"Bearer {root['token']}"},
        )
        elapsed = (time.perf_counter() - t0) * 1000
        if code == 201:
            samples.append(elapsed)
            children.append(body)
        else:
            print(f"  [delegate {i} failed: {code} {body}]")
    if samples:
        summarise("POST /tokens/delegate", samples)
    else:
        print("  POST /tokens/delegate                 no successful calls -- see errors above")

    # Revocation: the operation that took ~1.9s in the first live demo.
    samples = []
    for child in children[:5]:
        t0 = time.perf_counter()
        code, body = post("/tokens/revoke", {"jti": child["jti"]}, admin)
        elapsed = (time.perf_counter() - t0) * 1000
        if code == 200:
            samples.append(elapsed)
        else:
            print(f"  [revoke failed: {code} {body}]")
    if samples:
        summarise("POST /tokens/revoke (leaf, 1 token)", samples)
    else:
        print("  POST /tokens/revoke                   no successful calls")

    status, tree_root = post(
        "/tokens/root",
        {"human_id": "latency-probe-tree", "scopes": ["read_calendar"], "ttl_seconds": 900},
        admin,
    )
    token = tree_root["token"]
    chain_len = 0
    for level in range(3):
        code, body = post(
            "/tokens/delegate",
            {"child_agent_id": f"probe-chain-{level}", "requested_scopes": ["read_calendar"],
             "ttl_seconds": 600},
            {"Authorization": f"Bearer {token}"},
        )
        if code == 201:
            token = body["token"]
            chain_len += 1
    t0 = time.perf_counter()
    code, body = post("/tokens/revoke", {"jti": tree_root["jti"]}, admin)
    subtree_ms = (time.perf_counter() - t0) * 1000
    print(
        f"  {'POST /tokens/revoke (subtree)':<34} "
        f"1 call -> {subtree_ms:8.2f}ms  "
        f"({body.get('subtree_count')} tokens, server-measured "
        f"{body.get('latency_ms')}ms)"
    )

    samples = []
    for _ in range(10):
        t0 = time.perf_counter()
        request = urllib.request.Request(f"{API}/health")
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
        samples.append((time.perf_counter() - t0) * 1000)
    summarise("GET /health (4 count queries)", samples)

    print()
    print("=" * 78)
    print("INTERPRETATION")
    print("=" * 78)
    print(
        "Every figure above includes at least one round trip to Supabase in\n"
        "ap-northeast-1 (Tokyo) and/or Upstash. Compare against docs/results.md,\n"
        "where both datastores are in-process. The delta is network latency, not\n"
        "a change in the service's own work."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
