# Eval Harness Results

<!-- GENERATED FILE. Do not edit by hand.
     Regenerate with: python -m tests.generate_results -->

**Generated:** 2026-08-07 23:09:36 India Standard Time
**Python:** 3.12.10  
**Platform:** Windows 11 (AMD64)  
**Datastores:** SQLite in-memory (Postgres in production); fakeredis (Redis in production)

Every number here comes from executing the suite on the machine described above. Nothing is hand-written.

## Honest caveats

- Latency figures come from an **in-process** harness on SQLite + fakeredis. They are a lower bound for a containerised Postgres/Redis deployment across a network. Use `tests/locustfile.py` against `docker compose up` for a realistic figure.
- Latency assertions use a deliberately generous ceiling. The tests *report* the measured value rather than being tuned until they pass the PRD target; a benchmark trimmed to hit its own goal is not evidence.
- A green run here does not prove the Postgres path. Any change to `models/`, `revocation.py` or `db/session.py` needs the Layer-3 `docker compose` check.

## Eval items (PRD Section 10 + 16.4)

| # | Criterion | Status | Tests | Time |
|---|-----------|--------|-------|------|
| 1 | Scope escalation always fails | **PASS** | 524/524 | 30.0s |
| 2 | Legitimate narrowing always succeeds | **PASS** | 111/111 | 7.2s |
| 3 | Revocation propagation (incl. cache-loss safety) | **PASS** | 14/14 | 2.5s |
| 4 | Chain reconstruction accuracy | **PASS** | 13/13 | 2.4s |
| 5 | Circuit breaker trips correctly | **PASS** | 11/11 | 2.4s |
| 6 | Audit log tamper detection | **PASS** | 11/11 | 2.3s |
| 7 | Approval gate blocks until human action | **PASS** | 20/20 | 2.8s |
| 8 | Checkpoint latency benchmark | **PASS** | 4/4 | 4.5s |
| 9 | LangGraph adapter integration | **PASS** | 18/18 | 2.5s |

## Supporting suites

| Area | Status | Tests | Time |
|------|--------|-------|------|
| Config / secret hardening | **PASS** | 25/25 | 1.7s |
| Token engine (signature, expiry, claim schema) | **PASS** | 18/18 | 1.7s |
| API contract (PRD Section 6 shapes) | **PASS** | 34/34 | 3.2s |
| Rate limiting + anomaly flagging | **PASS** | 11/11 | 2.3s |
| Architectural boundary checks | **PASS** | 16/16 | 1.9s |
| End-to-end demo scenario (PRD Section 11) | **PASS** | 11/11 | 2.6s |

**Total: 841 passed, 0 failed.**

## Measured numbers

### Item 1 -- scope escalation block rate

```
[item 1] escalation block rate: 520/520 = 100.0%
```
The escalation matrix is parametrized over every (parent, requested) pair drawn from the 5 demo scopes where the request is not a subset. Target: 100% block rate, 0 false negatives.

### Item 3 -- revocation propagation

| Metric | Value | PRD target |
|--------|-------|-----------|
| Subtree revoke, p50 | 1.36 ms | < 50 ms |
| Subtree revoke, p95 | 1.69 ms | < 50 ms |
| Subtree revoke, max | 2.92 ms | < 50 ms |
| First post-revoke denial, p50 | 2.28 ms | -- |

Measured over 20 runs, each revoking the root of a 3-level chain (4 tokens). 'First post-revoke denial' is the full `/verify` round trip for a leaf token immediately after the revoke returned.

### Item 8 -- checkpoint latency

```
[item 8] /verify over 500 calls (in-process, SQLite+fakeredis):
p50=1.523ms  p95=2.527ms  p99=5.204ms
mean=1.698ms  throughput=589 req/s
PRD target: p95 < 20ms excluding network
NOTE: includes the ASGI/httpx TestClient round trip, so this is an
upper bound on the engine's own cost.
[item 8] DelegationEngine.verify() direct, 500 calls (no HTTP layer):
p50=0.163ms  p95=0.327ms  p99=4.830ms
PRD target: p95 < 20ms excluding network
[item 8] p95 latency vs delegation depth: depth=0: 3.274ms  depth=2: 2.719ms  depth=4: 2.745ms
[item 8] audit buffer steady state: first 200 p95=2.286ms, next 200 p95=2.281ms
```
Two figures are reported: through the full ASGI stack, and calling `DelegationEngine.verify()` directly. The PRD's target is qualified 'excluding network', so the direct figure is the closer comparison; the HTTP figure is the honest upper bound for an in-process caller.

## What each item actually proves

| # | The claim | How it is falsifiable |
|---|-----------|----------------------|
| 1 | A child can never hold a scope its parent lacks | Parametrized over the full non-subset matrix; a single 201 fails the suite |
| 2 | Any legitimate narrowing is honoured | Parametrized over every non-empty subset; also asserts `child.exp <= parent.exp` and depth limits |
| 3 | Revoking a root kills the whole subtree, durably | Verifies all 4 tokens are refused, then flushes the cache entirely and re-checks (fail-open guard) |
| 4 | Lineage cannot be fabricated | Chain is rebuilt from server records and cross-checked against the signed `delegation_chain` claim |
| 5 | The breaker opens on a genuine error spike | Synthetic spike, then asserts a *valid* token is refused with `circuit_open` |
| 6 | The audit log is tamper-evident | Five attack shapes: field mutation, decision flip, row deletion, forged row hash, backdating |
| 7 | No credential exists while approval is pending | Asserts the 202 body carries no token and no `token_record` row is created |
| 8 | Enforcement is cheap enough for the hot path | p50/p95/p99 reported at two layers, plus depth-scaling and buffer steady-state |
| 9 | A denied node's side effect never happens | Guarded nodes append to a list; the test asserts the list is empty after denial |

---

Reproduce with:

```bash
pip install -e ".[dev]"
pip install -e ./langgraph_adf_adapter
pytest -q
python -m tests.generate_results
```

