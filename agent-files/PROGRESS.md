# PROGRESS.md
# ============
# AGENT: Read this at the START of every session.
# AGENT: Update this at the END of every session before committing.
# AGENT: This file is your memory across sessions. Keep it accurate.

## Repo State
- Latest verified commit: **none — nothing has been committed**. Per user direction this
  folder has no git repo of its own (it sits inside the `ML` folder, which is a repo for
  the unrelated `Wholesale_Dealer_ERP` project). Do not stage or commit into the parent.
- `pytest -q` status: **848 passed, 0 failed** (verified 2026-08-07, ~46s)
- `python -m tests.check_boundaries`: **all 5 checks pass**
- `python -c "import checkpoint_service.main"`: **OK**
- `cd dashboard && npx tsc --noEmit`: **0 errors**
- `cd dashboard && npm run build`: **PASSING** (5 chunks, no size warnings)
- `docs/results.md`: regenerated from a real run (841 tests via the per-target runner)
- Last updated: 2026-08-07

## Build Status
- Python 3.12.10 in a **project-local venv at `.venv/`**. Use `.\.venv\Scripts\python.exe`.
  The venv exists because installing this project's pinned `pydantic==2.10.4` globally
  broke the user's other packages (langchain, google-genai, scrapegraphai need >=2.12.5).
  The global environment was restored; never `pip install` this project globally.
- Node 24.14.1 / npm 11.11.0 — dashboard deps installed, typecheck and build both clean.
- Docker 29.4.3 + Compose v5.1.4 available. `docker compose config -q` validates.
- Primary gate is `pytest -q` (SQLite + fakeredis, no Docker needed).

## Current Active Feature
- None. F01–F14 were built in one continuous bootstrap session at the user's explicit
  request ("build everything in one go"), which suspended WIP=1 for that session only.
- **WIP=1 now applies normally.** Any follow-up work must set exactly one
  `not_started` feature in `features.md` to `active` before touching code.

## Recently Completed
All fourteen features are `passing` with command output as evidence — see
`features.md` for the per-feature verification and numbers. Headline results:

- [x] Checkpoint Service: root/delegate/verify/revoke/approve/deny + audit + admin
      endpoints, strict-subset enforcement, hash-chained audit log, durable revocation.
- [x] Eval harness, all 9 PRD items passing. 100% escalation block rate over 520
      parent/request combinations; revocation p95 1.69ms; engine verify p95 0.33ms.
- [x] LangGraph adapter as an installable package; verified against a real compiled
      `StateGraph`, and proven to block a node *before* its side effect runs.
- [x] React dashboard (4 screens, 2s polling), typechecks and builds clean.
- [x] Demo agents + `run_demo.py` executing all 7 PRD Section 11 steps, usable as a
      smoke test (non-zero exit if any security expectation fails).
- [x] Docker Compose stack, Alembic migration, README security whitepaper,
      generated `docs/results.md`.
- [x] Five AST-based architectural boundary checks, each with a meta-test proving the
      detector actually fires on a broken sample.

## In Progress (Not Yet Verified)
- (nothing)

## Blocked
- (nothing blocking)

## Known Issues
<!-- Be specific. Vague issues help no one. -->
1. **`docker compose up` was never executed** (the user aborted the build). So the
   Layer-3 integration path is **unverified**: real Postgres, real Redis, the
   entrypoint's migration step, and the dashboard container have not been exercised
   together. `docker compose config -q` passes and the Alembic migration was applied
   successfully against SQLite, but that is not the same thing. **This is the single
   biggest known gap.** Run it before treating the stack as working.
2. The primary gate runs on SQLite + fakeredis. Green tests do **not** prove the
   Postgres/Redis path. Any change to `models/`, `engine/revocation.py` or
   `db/session.py` needs the Layer-3 check above.
3. Latency numbers in `docs/results.md` are in-process (no network, no real Postgres).
   They are a lower bound. Use `tests/locustfile.py` against a live stack for a
   realistic figure; that has not been run either.
4. `.env` in the repo root contains **real generated secrets** created for the compose
   attempt. It is gitignored, but it exists on disk — rotate or delete it if this
   directory is ever shared.
5. v1 admin auth is one shared static key with no per-human identity and no rotation
   flow beyond editing the env var and restarting. Documented in the README threat
   model as the weakest link.
6. `ADF_GUARDRAIL_EXEMPT_AGENTS` must be empty in production; an entry there is an
   unthrottled identity. The compose file sets it to `""` explicitly.
7. The audit hash chain is tamper-*evident*, not tamper-*proof*: an attacker with
   unrestricted DB write access can recompute the chain from the break onward.
   Mitigation (external notarisation of the chain tip) is documented, not implemented.
8. `verify_success` audit rows are buffered, so a hard crash can lose up to
   `ADF_AUDIT_BUFFER_MAX_SIZE` of them. Denials and mints are synchronous. This is a
   deliberate, documented trade — see DECISIONS.md.
9. No git history, so the ACID "one feature = one commit" checkpointing in
   HARNESS_ENGINEERING Part 2 cannot be applied yet.

## Next Steps
<!-- Ordered. The next session starts at item 1. -->
1. **Run the Layer-3 check** (Known Issue 1):
   `docker compose up -d --build`, then `curl -fsS http://localhost:8000/health`,
   then `python demo_agents/run_demo.py --admin-key $ADF_ADMIN_API_KEY`, then open the
   dashboard at http://localhost:8080. Fix anything that breaks and record the result
   in F13's evidence.
2. Run the real load test against that stack:
   `locust -f tests/locustfile.py --host http://localhost:8000 --headless -u 50 -r 10 -t 60s`
   and add the network-inclusive p95 to `docs/results.md` alongside the in-process one.
3. Decide on version control (the user chose "build in place, no git init"). If that
   changes, `git init` here and commit feature by feature.
4. Optional hardening, in rough value order: RS256 + JWKS (removes the shared-secret
   verifier problem), OIDC admin auth (gives `approved_by` a real identity), external
   notarisation of the audit chain tip.

## Decisions Made This Session
<!-- Summary — full detail in DECISIONS.md -->
Eleven decisions recorded, all of them resolving a PRD contradiction or a fail-open
design. The security-relevant ones:

- **Verify order fixed**: signature is checked before any claim is read. PRD §7's
  pseudocode reads `token.jti` from an unverified token.
- **Revocation made durable**: Postgres is the source of truth, Redis is a cache
  rebuilt at startup. PRD §8.4's Redis-only design fails **open** on restart.
  A cache-readiness sentinel was added after a test caught exactly that fail-open.
- **Approval gate mints on approval**: no JWT exists while a request is pending,
  resolving the PRD §5 vs §7 contradiction.
- **Opaque UUID subjects** in tokens with salted hashes in the audit log (PRD §8.6
  beats §5's `"human:jalp"` example).
- **Policy denials vs breaker faults separated**: a blocked escalation or a forged
  token no longer counts as a system fault, because counting them let any client open
  the circuit for everyone by spamming garbage.
- **`verify_success` audit writes buffered** through a single background writer;
  denials and mints stay synchronous.
- Plus: guardrail-exempt allowlist for the benchmark, `max_depth` as an optional
  per-root field, added `root_jti` claim, demo satisfies the approval gate rather than
  bypassing it, and measured-not-asserted latency targets.

---
<!-- AGENT REMINDER:
  - "In Progress" ≠ "Done". Only move to Completed after verification passes.
  - If pytest is FAILING when you write this, say so honestly.
  - The next session will trust this file. Make it trustworthy.
-->
