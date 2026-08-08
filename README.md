# Agent Delegation Firewall (ADF)

**Authorization and capability-narrowing for multi-agent AI pipelines.**

When one AI agent hands work to another, most frameworks copy or inherit the
caller's permissions. The sub-agent ends up able to do things the delegating agent
was never supposed to allow, and nothing records why it could. Google ADK's
delegation is LLM-judgment-based with no built-in permission narrowing; third
parties sell bolt-on authorization precisely because the frameworks do not solve
this natively; 2024–2025 papers propose `delegation_chain` and
`delegation_constraints` concepts without a reference implementation. ADF is that
missing piece as a standalone, framework-agnostic service: every delegation is
forced to be a **strict subset** of the parent's permissions, the whole chain of
custody is cryptographically traceable back to a human, revoking any token kills
its entire downstream subtree, and every decision lands in a tamper-evident log.

Measured on the machine in [`docs/results.md`](docs/results.md): **100% scope-
escalation block rate across 520 parent/request combinations**, **revocation
propagating in 1.7 ms p95**, and **enforcement costing 0.33 ms p95** in the engine
(2.5 ms through the full HTTP stack) — comfortably inside the 20 ms budget for
something that sits in front of every agent action.

```
                    ┌──────────────────────────────────────────────┐
   ┌──────────┐     │            CHECKPOINT SERVICE (FastAPI)      │     ┌──────────┐
   │  Human   │─────┤                                              ├─────│  Agents  │
   │ (X-Admin │mint │  ┌────────────┐      ┌──────────────────┐    │calls│ (native, │
   │  -Key)   │     │  │   Token    │      │    Delegation    │    │     │ LangGraph│
   └──────────┘     │  │   Engine   │─────▶│  Engine (⊆ check │    │     │  adapter)│
                    │  │  (PyJWT,   │      │  exp clamp,      │    │     └──────────┘
                    │  │   HS256)   │      │  depth ceiling)  │    │
                    │  └────────────┘      └──────────────────┘    │
                    │  ┌────────────┐      ┌──────────────────┐    │
                    │  │ Revocation │      │    Guardrails    │    │
                    │  │  Postgres  │      │  rate limit,     │    │
                    │  │  = truth   │      │  circuit breaker,│    │
                    │  │  Redis     │      │  approval gate,  │    │
                    │  │  = cache   │      │  anomaly flag    │    │
                    │  └────────────┘      └──────────────────┘    │
                    │  ┌────────────────────────────────────────┐  │
                    │  │  Audit Log — append-only, hash-chained  │  │
                    │  │  single writer, Postgres                │  │
                    │  └────────────────────────────────────────┘  │
                    └───────────────────────┬──────────────────────┘
                                            │ polled every 2s
                                ┌───────────▼────────────┐
                                │  React Dashboard       │
                                │  tree · audit · queue  │
                                │  · health/integrity    │
                                └────────────────────────┘
```

## How the core invariant works

A root token is minted for a human with some scope set. Every delegation from
there is checked against the **live parent token**, not against a stored record or
the request itself:

```
child.scopes    ⊆ parent.scopes      # equal is fine; exceeding is never
child.exp       ≤ parent.exp         # clamped, so a child cannot outlive its parent
child.depth     = parent.depth + 1   # rejected above max_depth
child.chain     = parent.chain + [parent's own entry]
root of chain must be live           # non-expired, non-revoked, depth-0
```

Because narrowing is transitive, an agent that lost a scope one hop ago cannot
re-grant it even though the root token had it. That is the case the tests hammer
hardest — see `test_grandchild_cannot_regain_parent_scope`.

## Two ways to use this

| | **`agperms`** (embeddable library) | **Checkpoint Service** (`checkpoint_service/`) |
|---|---|---|
| Install | `pip install agperms` | `docker compose up --build` |
| Needs | nothing — in-memory by default | Postgres + Redis |
| Enforcement | Python calls (`fw.verify(...)`) | HTTP (`POST /tokens/verify`) |
| Processes | **one** | many, sharing one authority |
| Signing key | held by whoever verifies | held only by the service |
| Dashboard | no | yes |

**Which one?** Use the library if enforcement lives inside a single process. Use the
service if any of these are true:

- **More than one process or machine shares one audit chain.** The chain's integrity
  depends on a single writer computing each row's hash from the current tail, enforced
  by an in-process lock. Two library instances against one database **fork the chain** —
  measured, not theorised. The service is that single writer.
- **Agents are not all Python.** A Node or Go agent cannot `import agperms`; HTTP is the
  only shared interface.
- **You want the approvals queue or delegation-tree UI**, which are HTTP + React.
- **The verifier must not hold the signing key.** HS256 means anyone who can verify can
  also mint. Centralising verification keeps the key in one place instead of on every
  service that checks a token.
- **The agent's own process is untrusted.** A library called from inside that process can
  be bypassed by it; a network boundary cannot.

They are the embedded and shared-authority forms of the same rules, not alternatives.

The library additionally implements **in-flight revocation forensics**: wrap
side-effecting work in `fw.action(...)` and a revoke reports whether each open
action was `CLEAN`, `PARTIAL` or `UNKNOWN`, rather than only telling you the token
stopped working. See [`agperms/README.md`](agperms/README.md).

```python
from agperms import Firewall

fw = Firewall()
root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])
child = fw.delegate(root.token, to="calendar-agent", scopes=["read_calendar"])

with fw.action(child.token, scope="read_calendar", name="read_agenda"):
    read_agenda()

for review in fw.revoke(root.jti).reviews:
    print(review.action_name, review.classification)
```

## Quickstart

```bash
# 1. Secrets. There are NO defaults; the service refuses to boot without them.
cp .env.example .env
python -c "import secrets; print('ADF_ADMIN_API_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('ADF_JWT_SECRET='    + secrets.token_urlsafe(48))"
python -c "import secrets; print('ADF_PII_SALT='      + secrets.token_urlsafe(16))"
# paste those into .env, replacing the change-me placeholders

# 2. Full stack: api + postgres + redis + dashboard
docker compose up --build
#   API      http://localhost:8000        (OpenAPI docs at /docs)
#   Dashboard http://localhost:8080

# 3. The scripted demo (PRD Section 11, all 7 steps)
python demo_agents/run_demo.py --admin-key "$ADF_ADMIN_API_KEY"
```

No Docker? Everything runs in-process against SQLite + fakeredis:

```bash
pip install -e ".[dev]"
pip install -e ./langgraph_adf_adapter

pytest -q                                  # 848 tests, the primary gate
python demo_agents/run_demo.py --in-process # the 7-step scenario
python demo_agents/langgraph_demo.py --in-process
python -m tests.generate_results            # regenerates docs/results.md
```

## API

Full reference is auto-generated at **`/docs`** (Swagger) and **`/openapi.json`**.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/v1/tokens/root` | `X-Admin-Key` | Mint a root token for a human |
| `POST /api/v1/tokens/delegate` | `Bearer <parent token>` | Mint a narrowed child token |
| `POST /api/v1/tokens/verify` | none needed | **The enforcement checkpoint** |
| `POST /api/v1/tokens/revoke` | `X-Admin-Key` | Revoke a token + its whole subtree |
| `POST /api/v1/tokens/approve` / `deny` | `X-Admin-Key` | Human decision on a sensitive scope |
| `GET /api/v1/tokens/pending/{id}` | none needed | Agent collects an approved token |
| `GET /api/v1/audit/chain/{jti}` | none needed | Full root→leaf lineage |
| `GET /api/v1/audit/log` | none needed | Filterable audit query |
| `GET /api/v1/audit/verify_integrity` | none needed | Walk the hash chain, name the first break |
| `GET /api/v1/audit/tree` / `approvals` | none needed | Dashboard views |
| `GET /health` | none needed | Breaker state + system status |
| `POST /api/v1/admin/circuit/reset` | `X-Admin-Key` | Break glass |

`/verify` is intentionally open to anyone holding a token: it reveals nothing the
token holder does not already possess. `/delegate` authenticates with the calling
agent's own capability token, so a caller can only ever narrow what it actually
holds.

Escalation returns exactly this (PRD 6.2), asserted field-by-field in the tests:

```json
{ "error": "scope_escalation_denied",
  "requested": ["web_search"], "allowed_max": ["send_email"],
  "denied_scopes": ["web_search"] }
```

## LangGraph adapter

```python
from langgraph_adf_adapter import ADFGuard

adf = ADFGuard(checkpoint_url="http://localhost:8000")

@adf.require_scope("send_email")           # node-entry guard
def email_node(state):
    ...                                     # body runs only if the token allows it

def assistant_node(state):
    # narrows the token before dispatching; raises on escalation
    return adf.delegate_for_node(state, "email-agent", ["send_email"])
```

The guard raises **before** the node body executes. The eval harness proves this
by having guarded nodes append to a list and asserting the list is still empty
after a denial — an exception raised *after* the side effect would be worthless.
Verified against a real compiled `StateGraph`, and the adapter installs as its own
package (`pip install -e ./langgraph_adf_adapter`).

## Threat model

**What ADF prevents**

- Privilege escalation across a delegation hop, transitively, at any depth.
- A child outliving its parent, or a chain rooted at a dead token.
- Silent capability grants: every mint, denial, and revocation is logged with lineage.
- Undetected log tampering: field edits, deletions, reordering, and forged row hashes
  all break the chain and are localised to the first bad row.
- Revocation being lost to infrastructure failure: Postgres is the source of truth
  and Redis is rebuilt from it, so a cache wipe cannot resurrect a revoked token.
- Sensitive capabilities being granted without a human: no JWT exists at all while
  an approval is pending.

**What ADF does NOT prevent — read this part**

- **A compromised Checkpoint Service.** It holds the HS256 signing key. Whoever
  controls this process can mint anything. ADF moves the trust boundary; it does
  not remove it.
- **A malicious or careless human root issuer.** ADF enforces that delegation only
  ever narrows. If a human mints a root token with `delete_data`, that is a valid
  grant and ADF will honour it.
- **Prompt injection causing harmful-but-in-scope actions.** If an agent legitimately
  holds `send_email` and is manipulated into sending a bad email, every check
  passes. ADF constrains *what* an agent can do, never *whether the intent was
  sound*. Pair it with content-level controls.
- **A leaked child token.** Tokens are bearer credentials. Anyone holding one has
  its scopes until it expires or is revoked. Mitigate with short TTLs (the demo
  uses 600 s) and revoke on suspicion.
- **A stolen admin key.** It is a single shared static key in v1 with no per-human
  identity and no rotation flow beyond changing the env var and restarting. This is
  the weakest link in the v1 design and is called out as such.
- **Tampering by someone who can rewrite the whole audit table.** The hash chain is
  tamper-*evident*, not tamper-*proof*. An attacker with unrestricted database write
  access can recompute every row from the break onward. Ship the chain tip somewhere
  append-only (or notarise it) to close this.
- **Crash-loss of buffered verify events.** `verify_success` rows are batched by a
  background writer, so a hard crash can lose up to `ADF_AUDIT_BUFFER_MAX_SIZE`
  of them. Every *denial* and every *mint* is synchronous and durable before the
  caller is told the outcome — the deliberate asymmetry is explained in
  `agent-files/DECISIONS.md`.
- **Guardrail-exempt agents.** `ADF_GUARDRAIL_EXEMPT_AGENTS` exists so the latency
  benchmark measures the checkpoint rather than the rate limiter. An entry there is
  an unthrottled identity. **Keep it empty in production.**

## Results

Full detail with the environment it was measured in: [`docs/results.md`](docs/results.md).

| Eval item | Result |
|---|---|
| 1. Scope escalation always fails | **100%** block rate, 520/520 combinations, 0 false negatives |
| 2. Legitimate narrowing always succeeds | 111/111 subset cases pass |
| 3. Revocation propagation | p50 **1.28 ms**, p95 **1.69 ms** (target < 50 ms) |
| 4. Chain reconstruction accuracy | Server-side rebuild matches the signed claim exactly |
| 5. Circuit breaker | Trips within one window; no auto-recovery; break-glass only |
| 6. Audit tamper detection | 5 attack shapes caught, first broken row identified |
| 7. Approval gate | 202 carries no token; no `token_record` row while pending |
| 8. Checkpoint latency | engine p95 **0.33 ms**; via HTTP p95 **2.53 ms** (target < 20 ms) |
| 9. LangGraph integration | Denied node's side effect provably never occurs |

**848 tests, 0 failures.** Latency figures are from an in-process harness on
SQLite + fakeredis; use `tests/locustfile.py` against `docker compose up` for a
figure that includes real network and Postgres costs.

## Deliberate deviations from the PRD

The PRD contains several internal contradictions and two designs that fail open.
Each resolution is recorded in [`agent-files/DECISIONS.md`](agent-files/DECISIONS.md);
do not "fix" these back without reading the entry.

| PRD says | ADF does | Why |
|---|---|---|
| §7 `verify()` reads `token.jti` for the revocation check first | Signature verified **before any claim** is read | `jti` is attacker-controlled until the signature checks out |
| §8.4 revocation lives only in Redis | Postgres is truth, Redis is a rebuilt cache | Redis-only fails **open** on restart: revoked tokens become valid again |
| §5/§7 disagree on whether a pending approval has a token | No JWT exists until approval; minted in the approve handler | Mint-then-mark puts a live credential in circulation whose safety depends on every verifier remembering a side table |
| §8.5 + item 8 want a synchronous hash chain *and* p95 < 20 ms | `verify_success` batched via a single background writer; all denials/mints synchronous | The chain's `prev_hash` is a read-modify-write on the tail row — a serialization point on the hottest path |
| §5 example embeds `"human:jalp"`; §8.6 demands opaque ids | Opaque `human:<uuid>` in tokens; salted hashes in the log; labels resolved server-side | The token is exactly the artifact that crosses the trust boundary |
| §11 demo has `send_email` succeed instantly; §8.2 makes it sensitive | Demo returns 202, then performs the human approval explicitly | Both cannot be true; showing the gate beats hiding it |
| §5 `max_depth` "from root config", §6.1 has no such field | Optional per-root field, default `ADF_MAX_DELEGATION_DEPTH=5`, immutable in descendants | The value had no defined origin |
| §8.3 counts policy denials toward the breaker | Configurable (`ADF_CIRCUIT_COUNT_POLICY_DENIALS`, default on per PRD) | Counting them lets a hostile client open the breaker for everyone by spamming denied requests |
| — | Added `root_jti` claim | Lets root liveness be checked without walking a client-supplied array |

## Upgrade path

| Concern | v1 | Production |
|---|---|---|
| Signing | HS256, one shared secret; every verifier needs it | RS256/EdDSA: swap `jwt_algorithm` + key loading in `token_engine.py`, publish a JWKS endpoint, and verifiers only need the public key |
| Admin auth | One static `X-Admin-Key` | OIDC with per-human identity, so `approved_by` names a real person and rotation is not a restart |
| Revocation cache | Single Redis | Redis Cluster or Sentinel; correctness already survives total cache loss, so this is purely a latency/HA concern |
| Audit store | Single Postgres | Streaming replication + PITR; periodically notarise the chain tip externally to close the "attacker rewrites everything" gap |
| Audit durability | In-process buffer for verify events | Append to a durable queue (Kafka/Kinesis) with the same single-writer chain discipline downstream |
| Deployment | One instance | Horizontal API replicas are fine (state is in Postgres/Redis) **except** the audit writer — elect one writer per chain, or shard chains per instance |
| Rate limiting | Per-agent sliding window | Same, but ensure Redis is shared so the window is global rather than per-replica |

## Repository layout

```
checkpoint_service/     FastAPI service (hosted mode)
  config.py             settings; refuses to boot on weak/placeholder secrets
  models/               Pydantic token schema + SQLAlchemy tables
  engine/               token_engine, delegation_engine, revocation,
                        guardrails, audit_logger, subjects
  routes/               /tokens, /audit, /health + /admin
agperms/                embeddable library (pip install agperms)
  src/agperms/          Firewall facade, engines, models, errors
    storage/            Storage protocol + MemoryStorage + SqlStorage
    integrations/       LangGraph guard with automatic checkpointing
  tests/                366 tests, both storage backends
langgraph_adf_adapter/  HTTP client for the hosted service (ADFGuard, ADFClient)
dashboard/              React + Vite + TS + Tailwind console (4 screens)
demo_agents/            toy agents, run_demo.py (PRD §11), langgraph_demo.py
tests/                  848 tests: 9 eval items + supporting suites, locustfile
migrations/             Alembic
agent-files/            AGENTS.md, PROGRESS.md, features.md, DECISIONS.md,
                        HARNESS_ENGINEERING.md
docs/                   PRD.md (original spec), results.md, results-remote.md
```

Working on this codebase: start with [`agent-files/AGENTS.md`](agent-files/AGENTS.md).
It carries the hard constraints, the verification commands, and the session ritual.
