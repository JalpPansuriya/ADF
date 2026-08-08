# Eval Results — Live Hosted Backends (Supabase + Upstash)

<!-- GENERATED FILE. Do not edit by hand.
     Regenerate with: python scripts/generate_remote_results.py
     (requires the API running against the hosted backends) -->

**Generated:** 2026-08-08 09:56:13 India Standard Time

This is the companion to [`results.md`](results.md). That file measures the in-process harness (SQLite + fakeredis in the same process); this one measures the **deployed topology** — managed Postgres and managed Redis reached over the public internet. The functional guarantees are identical in both. The latency is not, by three orders of magnitude, and the reason is geography rather than anything the service does.

## Environment

| Component | Detail |
|---|---|
| Client / API host | Windows 11, Python 3.12.10 (local workstation, IST / UTC+05:30) |
| Postgres | PostgreSQL 17.6 — Supabase |
| Postgres endpoint | `postgresql+psycopg://postgres.bcsedgwybppopvhebunl:***@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres` |
| Redis | 8.2.0 — Upstash, maxmemory 64.000MB |
| Redis endpoint | `rediss://default:***@fine-reptile-140305.upstash.io:6379` |
| Redis TLS | yes (rediss://) |
| Schema | 7 tables, applied by `alembic upgrade head` |

The API ran on the local workstation while both datastores are hosted in distant regions (the Supabase project is in `ap-northeast-1`, Tokyo). Every database call is therefore an intercontinental round trip. That is the single most important fact for reading the numbers below.

## Functional verification

The full PRD Section 11 scenario, executed against the live stack (wall clock: 50.3s for all seven steps):

| Property | Expected | Observed | Result |
|---|---|---|---|
| Scope escalation refused | 403, no token minted | denied_scopes = `['web_search']` | **PASS** |
| Sensitive scope held at approval gate | 202, human required | approval_id issued (`c1bb5608…`) | **PASS** |
| Root revocation kills subtree | all descendants refused | 3 tokens revoked, all fail `/verify` | **PASS** |
| Lineage reconstructed server-side | root→leaf chain | 2 hops returned | **PASS** |
| Audit chain intact | hash chain verifies | 358 rows checked | **PASS** |
| Only granted actions executed | least privilege honoured | performed `['calendar:read_agenda', 'email:send_summary']`, blocked `['calendar-agent:write_calendar']` | **PASS** |

The integrity walk covered **358 rows** written across more than one server process and reassigned pooler connections, and reported `intact: true`. That is the property the single-writer design exists to protect: concurrent or interleaved writers would fork the chain and the walk would find a break.

## Durability: revocation survives cache loss

The most security-critical behaviour in the system, tested against real infrastructure rather than a fake. ADF's cache keys were deleted from Upstash — exactly what a Redis restart does — and a **previously revoked token was presented again**:

| Step | Value |
|---|---|
| Revoked jtis in cache before | 36 |
| Cache keys deleted | 17 |
| Revoked jtis in cache after deletion | 0 |
| Readiness sentinel after deletion | `None` |
| `/verify` on a revoked token | HTTP 401, reason `revoked` |
| Still refused? | **YES — fail-closed** |
| Revoked jtis in cache after self-repair | 36 |

With an empty cache the lookup fell through to Postgres, refused the token, and rebuilt the cache from the durable record. The PRD specified Redis as the sole revocation store; that design would have answered `valid: true` here, because an empty set is indistinguishable from "nothing is revoked". The readiness sentinel is what makes the difference — its absence marks the cache as untrustworthy rather than empty.

Independently confirmed at process level: restarting the API logged `Revocation cache rebuilt: 3 revoked jtis, 2 edges`, repopulating Upstash from Supabase before serving any traffic.

## Latency

### Baseline: raw round trip to each backend

| Operation | n | p50 | p95 | max |
|---|---|---|---|---|
| Postgres `SELECT 1` (warm pooled conn) | 20 | 249 ms | 261 ms | 272 ms |
| Redis `PING` | 20 | 190 ms | 230 ms | 270 ms |
| Redis `SISMEMBER` (revocation read) | 20 | 209 ms | 261 ms | 262 ms |

**This is the floor.** No amount of application optimisation gets an operation below the cost of the round trips it must make. A single `SELECT 1` already costs ~249 ms, which is 12× the PRD's entire 20 ms budget for `/verify`.

### API operations

| Operation | n | p50 | p95 | max | Notes |
|---|---|---|---|---|---|
| `POST /tokens/verify` — allow | 30 | 1715 ms | 3272 ms | 5064 ms | hot path |
| `POST /tokens/verify` — deny (scope) | 15 | 1467 ms | 2674 ms | 2688 ms | scope_not_granted |
| `POST /tokens/delegate` | 8 | 3818 ms | 5826 ms | 5826 ms | mint + edge + audit write |
| `POST /tokens/revoke` — single token | 5 | 2057 ms | 2210 ms | 2210 ms |  |
| `GET /health` | 5 | 3143 ms | 3884 ms | 3884 ms | 4 aggregate COUNT queries |
| `POST /tokens/revoke` — subtree | 1 | 3362 ms | — | — | 4 tokens (depth 3 chain); server-measured 2222 ms |

### In-process vs hosted

| Operation | In-process (SQLite + fakeredis) | Hosted (Supabase + Upstash) | Ratio |
|---|---|---|---|
| `/verify` p50 | 1.5 ms (HTTP) / 0.16 ms (engine) | 1715 ms | ~1143× |
| `/delegate` p50 | ~2 ms | 3818 ms | ~1909× |
| Subtree revoke | 1.7 ms p95 | 3362 ms | ~1978× |

The service does the same work in both columns: verify a signature, check expiry, look up revocation, compare scopes, buffer an audit row. The gap is network distance. Confirmation that it is not the application: the server's own measurement of the subtree revoke was 2222 ms against 3362 ms of wall clock, and the remainder is time on the wire.

**The PRD's p95 < 20 ms target is unreachable in this deployment and would be**
**dishonest to claim.** To approach it, co-locate the API with the datastores:

- run the API in the same region as the Supabase project (`ap-northeast-1`)
- use an Upstash region in that same region
- prefer the pooler's session mode, or a direct connection, for long-lived processes

With all three in one region, intra-datacentre round trips are sub-millisecond and the in-process figures become a realistic guide again. That is a deployment decision, not a code change.

## Guardrails observed in the wild

- **Circuit breaker opened during measurement** (observed). The script issues a burst of 15 deliberately-denied verifies, which pushes the rolling error rate past the 25% threshold. The breaker did what it is supposed to do and refused subsequent traffic with `circuit_open`; the script resets it via the break-glass endpoint and continues. Worth stating plainly: the load generator was the hostile client here, and the guardrail caught it.
- **Rate limiting** stayed clear of the defaults (60 delegate/min, 300 verify/min per agent) because sample sizes are deliberately small; at these latencies the wire, not the limiter, is the constraint.
- **Approval gate** held the `send_email` delegation with no token minted until a human approved, then released exactly one token.

## Persisted state after the run

| Table | Rows |
|---|---|
| `token_record` | 53 |
| `audit_log` | 358 |
| `revocation` | 36 |
| `delegation_edge` | 41 |
| `pending_approval` | 3 |
| `subject_map` | 32 |

Redis held the readiness sentinel and 36 revoked jtis at the end of the run, mirroring Postgres. Counts reported by `/health`: {'tokens': 53, 'revocations': 36, 'audit_rows': 358, 'pending_approvals': 0}.

## Bugs this run exposed that the in-process harness could not

Worth recording explicitly, because it is the argument for testing against real infrastructure at all. All three are fixed; see `agent-files/DECISIONS.md`.

| # | Symptom | Root cause | Why SQLite/fakeredis missed it |
|---|---|---|---|
| 1 | `alembic upgrade head` appeared to succeed but created nothing | `migrations/env.py` read only `os.getenv`, never `.env`, so it targeted `localhost:5432` | The harness calls `create_all()` directly and never invokes Alembic |
| 2 | Every `audit_log` INSERT returned HTTP 500: `prepared statement "_pg3_1" does not exist` | Supabase's transaction pooler reassigns backend connections; psycopg's cached prepared statements are per-backend | SQLite has no prepared-statement cache and no connection pooler |
| 3 | Redis refused every connection with `Connection closed by server` | Upstash requires TLS; the URL used `redis://` instead of `rediss://` | fakeredis is in-process and has no transport layer at all |

Note the shape of bug 1: a migration tool that silently points at the wrong database is more dangerous than one that crashes, because it reports success. It surfaced here only because no local Postgres was listening.

## Reproducing this

```bash
# 1. Point .env at the hosted backends
#    ADF_DATABASE_URL=postgresql+psycopg://...pooler.supabase.com:6543/postgres
#    ADF_REDIS_URL=rediss://default:***@....upstash.io:6379

# 2. Confirm both are reachable and inspect the schema
python scripts/check_backends.py

# 3. Apply migrations to the hosted database
python -m alembic upgrade head

# 4. Start the API against them
python -m uvicorn checkpoint_service.main:app --host 127.0.0.1 --port 8000

# 5. Regenerate this document from a live run
python scripts/generate_remote_results.py
```

Helper scripts: `scripts/check_backends.py` (connectivity, schema, row counts), `scripts/probe_redis_scheme.py` (determines whether an endpoint needs TLS), `scripts/measure_remote_latency.py` (attributes latency to raw RTT vs API calls). All redact credentials in their output.

