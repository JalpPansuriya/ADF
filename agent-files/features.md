# features.md
# ==================
# AGENT: This is the single source of truth for what needs to be built.
# AGENT: Do NOT rely on conversation history for task state — use this file.
# AGENT: Only ONE feature may be `active` at a time (WIP=1).
# AGENT: You cannot change a feature to `passing` yourself.
#        Run its verification command. If it passes, update state to `passing`.

## Rules
1. Pick the next `not_started` feature in order.
2. Set it to `active`. No other feature may be `active` simultaneously.
3. Work on it until its verification command passes.
4. Update state to `passing`. Add evidence (command output or commit hash).
5. Only then move to the next feature.

## Feature States
- `not_started` — not yet begun
- `active` — currently being worked on (only ONE allowed at a time)
- `blocked` — cannot proceed, external dependency or ambiguity
- `passing` — verification command executed and passed (irreversible)

## Session note (2026-08-07)
F01–F14 were implemented in a single bootstrap session at the user's explicit request
("build everything in one go"), which suspended WIP=1 for that session. WIP=1 applies
normally from now on. All evidence below is real command output from that session, run
with the project venv (`.\.venv\Scripts\python.exe`).

---

## Features

### F01: Config + secret hardening (service refuses unsafe boot)
- **Behavior**: `get_settings()` raises `ConfigurationError` when `ADF_ADMIN_API_KEY`,
  `ADF_JWT_SECRET` or `ADF_PII_SALT` is missing, too short, or a `change-me` placeholder.
  Sensitive scopes load from `sensitive_scopes.yaml`. Guardrail-exempt agents and CORS
  origins accept comma-separated env values.
- **Verification**: `pytest tests/test_config.py -q`
- **State**: `passing`
- **Evidence**: `25 passed in 0.07s`. Includes a test that parses `.env.example` itself
  and asserts every shipped placeholder is rejected, so the template can never be used
  as-is. Also covers malformed `sensitive_scopes.yaml` being a hard error rather than a
  silent empty list (which would disable the approval gate).
- **Notes**: PRD §9/§15. Hard Constraint 6.

---

### F02: Token schema + Token Engine (mint/decode, HS256)
- **Behavior**: `TokenClaims` mirrors PRD §5 (plus `root_jti`). `TokenEngine` mints root
  and child tokens and decodes them with signature + issuer + required-claim
  verification.
- **Verification**: `pytest tests/test_token_engine.py -q`
- **State**: `passing`
- **Evidence**: `18 passed in 0.05s`. Beyond the PRD's requirements this also proves
  `alg: none` algorithm-confusion is rejected, that the claim schema is closed (an
  injected `is_admin` claim fails validation rather than riding along), and that a token
  signed by another deployment's secret does not verify.
- **Notes**: Subjects are opaque UUIDs, never human names (Hard Constraint 5).

---

### F03: Hash-chained append-only audit log + integrity walker
- **Behavior**: Every write stores `prev_hash` and
  `row_hash = sha256(prev_hash + canonical_row_content)`. `verify_integrity()` walks the
  chain and reports the id of the first broken row. `verify_success` events are buffered
  and flushed by a single background writer; all other event types write synchronously.
- **Verification**: `pytest tests/test_audit_integrity.py -q` (eval item 6)
- **State**: `passing`
- **Evidence**: `11 passed in 0.67s`. Five distinct tamper shapes are caught: field
  mutation, decision flip (allow↔deny), row deletion, forged `row_hash`, and timestamp
  backdating. Also asserts the chain does not fork when buffered and synchronous writes
  interleave, and that the first (not last) break is reported.
- **Notes**: PRD §8.5. A dedicated `event_ts` string column exists because SQLite drops
  tzinfo on round-trip, so hashing `ts.isoformat()` would fail on every read.

---

### F04: Delegation Engine — strict subset, expiry clamp, depth ceiling, chain build
- **Behavior**: `/tokens/delegate` mints a child only when `requested ⊆ parent.scopes`;
  otherwise `403 scope_escalation_denied` with `requested`/`allowed_max`/`denied_scopes`.
  `child.exp = min(now+ttl, parent.exp)`. `child.depth = parent.depth + 1`, rejected
  above `max_depth`. Chains whose root is expired or revoked are rejected.
- **Verification**: `pytest tests/test_delegation_rules.py -q` (eval items 1, 2)
- **State**: `passing`
- **Evidence**: `642 passed in 33.80s`. Measured escalation block rate:
  **520/520 = 100.0%, 0 false negatives** across every non-subset (parent, requested)
  pair from the 5 demo scopes. Separately proves a denial creates no `token_record` row,
  that narrowing is transitive (a grandchild cannot regain a scope its parent dropped),
  and that a forged/expired/revoked parent token cannot delegate at all.
- **Notes**: The core invariant of the product.

---

### F05: Revocation with subtree kill (Postgres truth + Redis cache)
- **Behavior**: Mint persists a `parent→child` edge. `/tokens/revoke` BFS-walks
  descendants and revokes the subtree in one transaction, returning `subtree_count`.
  `is_revoked()` is an O(1) Redis lookup with a Postgres fallback. Cache is rebuilt from
  Postgres on startup.
- **Verification**: `pytest tests/test_revocation.py -q` (eval item 3)
- **State**: `passing`
- **Evidence**: `14 passed in 0.86s`. Measured propagation: **p50 1.28ms, p95 1.69ms**
  (target < 50ms). `test_revocation_survives_total_cache_loss` **caught a real
  fail-open** during development — with Redis reachable but flushed, an empty revocation
  set was being trusted as "nothing revoked". Fixed with a cache-readiness sentinel;
  the test now flushes the whole cache and confirms revoked tokens are still refused.
- **Notes**: PRD §8.4 stored revocation only in Redis, which fails **open** on restart.
  See DECISIONS.md 2026-08-07 (revocation durability).

---

### F06: Guardrails — rate limit, circuit breaker, approval gate, anomaly flag
- **Behavior**: Sliding-window per-agent rate limits (`429`). Circuit breaker opens on
  rolling error rate or volume ceiling; while open `/verify` returns `401 circuit_open`
  and `/delegate` is blocked until the break-glass admin reset. Sensitive-scope
  delegations return `202` and expire after the timeout. Exempt agents bypass rate
  limiting and breaker accounting. Anomalies are logged, never auto-blocked.
- **Verification**: `pytest tests/test_circuit_breaker.py tests/test_rate_limit.py tests/test_approval_gate.py -q` (eval items 5, 7)
- **State**: `passing`
- **Evidence**: `11 + 11 + 20 = 42 passed`. Breaker trips within one window and refuses
  a *valid* token with `circuit_open`; does not trip below `min_samples` or at a low
  error rate; has no automatic recovery. Rate limits are proven per-agent (one noisy
  agent cannot starve another) and un-chargeable to a forged identity.
- **Notes**: Two real defects were found here by the tests. (a) A flood of forged tokens
  opened the breaker for everyone — forged tokens are now classified as policy denials,
  not system faults. (b) The anomaly detector could never fire on a zero-variance
  baseline, because the sigma test is vacuous when std = 0; it now falls back to a
  relative margin.

---

### F07: API surface — /tokens/*, /audit/*, /health, /admin
- **Behavior**: All PRD §6 endpoints, plus `GET /tokens/pending/{approval_id}`,
  `GET /audit/verify_integrity`, `GET /audit/tree`, `GET /audit/approvals`, and
  `POST /admin/circuit/reset`. Admin routes compare the key with
  `secrets.compare_digest`.
- **Verification**: `pytest tests/test_api_contract.py -q`
- **State**: `passing`
- **Evidence**: `34 passed in 1.50s`. The 403 escalation body is asserted as an exact
  dict match against PRD §6.2. Unknown request fields are rejected (`extra="forbid"`), so
  a typo'd `maxDepth` fails loudly instead of being silently ignored. `/health` is proven
  to leak no token material or secrets, and the OpenAPI schema is checked to contain
  every documented path.
- **Notes**: —

---

### F08: Chain reconstruction from server-side records
- **Behavior**: `GET /audit/chain/{jti}` returns the full root→leaf lineage rebuilt from
  `token_record`/`delegation_edge`, with per-hop scopes, depth, revoked/expired flags and
  labels resolved from `subject_map`.
- **Verification**: `pytest tests/test_audit_chain.py -q` (eval item 4)
- **State**: `passing`
- **Evidence**: `13 passed in 0.80s`. The server-side rebuild is cross-checked against
  the signed `delegation_chain` claim (two independent representations must agree), and
  scope sets are asserted to be monotonically narrowing down the chain. Also confirms the
  raw human id never appears in any audit row.
- **Notes**: Rebuilding server-side is the point — a caller must not be able to fabricate
  its own provenance.

---

### F09: LangGraph adapter package (installable)
- **Behavior**: `pip install -e ./langgraph_adf_adapter` exposes `ADFGuard` with
  `require_scope(scope)` and `delegate_for_node(...)`, plus a thin `ADFClient`.
- **Verification**: `pytest tests/test_langgraph_adapter.py -q` (eval item 9)
- **State**: `passing`
- **Evidence**: `18 passed in 0.91s`. Guarded nodes append to a module-level list and the
  tests assert the list is **empty** after a denial — proving the side effect never
  happened, not merely that an exception surfaced. Also verified end-to-end against a
  real compiled `StateGraph` via `python demo_agents/langgraph_demo.py --in-process`
  ("executed via: compiled LangGraph StateGraph", "new side effects after the denial:
  none").
- **Notes**: PRD §16. `pyproject.toml` needed an explicit `package-dir` map because the
  package source sits alongside it rather than in a nested directory.

---

### F10: Latency benchmark for /verify
- **Behavior**: Reports p50/p95/p99 and throughput at two layers, run as an exempt agent
  so guardrails do not distort the measurement. `tests/locustfile.py` provides the same
  measurement under real HTTP.
- **Verification**: `pytest tests/test_load_verify.py -q -s` (eval item 8)
- **State**: `passing`
- **Evidence**: `4 passed in 2.80s`. Measured: engine-direct **p50 0.163ms / p95 0.327ms**;
  through the full ASGI stack **p50 1.523ms / p95 2.527ms** (PRD target: p95 < 20ms
  excluding network). Latency is flat across delegation depth 0→4, and the audit buffer
  shows no degradation between the first and second 200 calls.
- **Notes**: Assertions use a generous ceiling and the tests *report* the number rather
  than being tuned to the target. `locustfile.py` has **not** been run against a live
  stack yet — see PROGRESS.md Known Issue 3.

---

### F11: Demo agents + scripted Section 11 scenario
- **Behavior**: `run_demo.py` runs the 7-step PRD §11 script end to end and exits
  non-zero if any security expectation fails. Deterministic by default;
  `ADF_LLM_MODE=1` enables real LLM planning.
- **Verification**: `pytest tests/test_demo_scenario.py -q`
- **State**: `passing`
- **Evidence**: `11 passed in 0.95s`, plus a real run of
  `python demo_agents/run_demo.py --in-process` printing all 7 steps and
  "Demo completed: all security expectations held." Observed: escalation blocked with
  `denied_scopes=['web_search']`, 3 tokens revoked in 3.56ms, 12 hash-chained audit rows
  intact, performed actions exactly `['calendar:read_agenda', 'email:send_summary']`.
- **Notes**: `send_email` is sensitive, so the demo performs the human approval step
  explicitly rather than hiding it (resolves the PRD §11 vs §8.2 contradiction).

---

### F12: React dashboard (4 screens, polling)
- **Behavior**: Vite + React + TS + Tailwind app with Delegation Tree, Audit Log table
  (with a JWT-claims detail drawer), Approvals Queue, and System Health (breaker state,
  error-rate chart, on-demand integrity check). Polls every 2s via TanStack Query.
- **Verification**: `cd dashboard && npx tsc --noEmit && npm run build`
- **State**: `passing`
- **Evidence**: `tsc --noEmit` produced no output (0 errors); `npm run build` succeeded
  in 4.62s with 5 chunks and **no chunk-size warnings** after splitting the recharts /
  react-d3-tree / vendor bundles.
- **Notes**: PRD §17, replacing the Streamlit dashboard from §12. The admin key is held
  in React state only, never in localStorage — otherwise any XSS would lift a credential
  that can mint roots and revoke anything.

---

### F13: Containerized one-command spin-up
- **Behavior**: `docker compose up --build` starts api + redis + postgres + dashboard;
  the API applies migrations on boot and `/health` reports ready.
- **Verification**: `docker compose config -q && docker compose up -d --build && curl -fsS http://localhost:8000/health`
- **State**: `blocked`
- **Evidence**: **PARTIAL ONLY.** `docker compose config -q` passes. The Alembic
  migration was generated and applied successfully (`alembic upgrade head` →
  "Running upgrade -> 0acadfc52c3e, initial schema"), though against SQLite, not
  Postgres. `docker compose up --build` was **started and then aborted by the user**, so
  the container images have never been built and the stack has never run.
- **Blocker**: needs a `docker compose up -d --build` run. Until then the entrypoint's
  wait-for-Postgres + migrate step, the non-root container user, the healthchecks, the
  real Postgres/Redis path and the nginx-served dashboard are all **unverified**.
- **Notes**: This is PROGRESS.md Known Issue 1 and the top item in Next Steps. Do not
  mark `passing` without the actual command output.

---

### F14: README security whitepaper + results.md
- **Behavior**: README contains the problem statement, architecture diagram, quickstart,
  API reference, an explicit threat model of what ADF does **not** protect against, the
  measured results table, and upgrade paths. `docs/results.md` is generated from a real
  run.
- **Verification**: `python -m tests.generate_results && pytest -q`
- **State**: `passing`
- **Evidence**: `docs/results.md` regenerated from a real run (`Total: 841 passed,
  0 failed` via the per-target runner) with the environment recorded; full-suite
  `pytest -q` → `848 passed in 45.93s`. README numbers were updated to match this run
  rather than an earlier one.
- **Notes**: The threat model names eight things ADF does not stop, including a
  compromised Checkpoint Service, a malicious root issuer, in-scope prompt injection, a
  stolen admin key, and the fact that the hash chain is tamper-*evident* rather than
  tamper-*proof*.

---

### F15: Executable architectural boundary checks
- **Behavior**: AST-based checks enforcing the Hard Constraints from AGENTS.md: no
  unverified decode on the enforcement path, no Postgres-only column types in `models/`,
  no `==` comparison of secrets, no UPDATE/DELETE of `audit_log` in service code, and no
  non-empty defaults for secrets.
- **Verification**: `python -m tests.check_boundaries` and `pytest tests/test_boundaries.py -q`
- **State**: `passing`
- **Evidence**: "All 5 architectural boundary checks passed" and `16 passed in 0.28s`.
  Each check has a **meta-test that feeds it a deliberately broken sample** and asserts
  it fires, so a refactor cannot silently neuter the file while leaving the suite green.
- **Notes**: Added because a rule written only in prose gets violated eventually
  (HARNESS_ENGINEERING Part 7). Uses AST parsing rather than grep: a text search for
  "JSONB" matches the docstring in `models/base.py` that explains why JSONB is banned,
  and a check that fires on its own documentation gets muted.

---

## Completed Features
<!-- These have already been verified and are immutable. -->
- [x] F01 Config + secret hardening — `25 passed`
- [x] F02 Token schema + Token Engine — `18 passed`
- [x] F03 Hash-chained audit log — `11 passed`
- [x] F04 Delegation Engine (strict subset) — `642 passed`, 100% block rate
- [x] F05 Revocation + subtree kill — `14 passed`, p95 1.69ms
- [x] F06 Guardrails — `42 passed`
- [x] F07 API surface — `34 passed`
- [x] F08 Chain reconstruction — `13 passed`
- [x] F09 LangGraph adapter — `18 passed`
- [x] F10 Latency benchmark — `4 passed`, engine p95 0.327ms
- [x] F11 Demo agents + §11 scenario — `11 passed`
- [x] F12 React dashboard — tsc clean, build clean
- [x] F14 README + results.md — regenerated from a real run
- [x] F15 Boundary checks — `16 passed`

**Not complete: F13 (docker compose) — `blocked`, never run.**

---
<!--
GRANULARITY GUIDE:
  Too broad (bad):  "Build the firewall"
  Too narrow (bad):  "Add a type hint to mint_child"
  Just right:       "Delegation Engine rejects any superset request with 403 scope_escalation_denied"

Each feature should be completable in one session.
Verification must be an executable command, not a description.
-->
