# PROGRESS.md
# ============
# AGENT: Read this at the START of every session.
# AGENT: Update this at the END of every session before committing.
# AGENT: This file is your memory across sessions. Keep it accurate.

## Repo State
- Latest verified commit: `9433082` (results-remote.md), remote
  `https://github.com/JalpPansuriya/ADF.git`, branch `main`. The `agperms` library and the
  Study Material folder are **on disk but not yet committed** — see Next Steps.
- `pytest -q` status: **848 passed, 0 failed** (hosted service, verified 2026-08-08, ~49s)
- `pytest agperms/tests -q` status: **366 passed, 0 failed** (embeddable library, ~2s)
- `python -m tests.check_boundaries`: **all 5 checks pass**
- `python -c "import checkpoint_service.main"`: **OK**
- `cd dashboard && npx tsc --noEmit`: **0 errors**
- `cd dashboard && npm run build`: **PASSING** (5 chunks, no size warnings)
- `docs/results.md`: regenerated from a real run (841 tests via the per-target runner)
- `docs/results-remote.md`: generated from a live Supabase + Upstash run
- Last updated: 2026-08-08

## Build Status
- Python 3.12.10 in a **project-local venv at `.venv/`**. Use `.\.venv\Scripts\python.exe`.
  The venv exists because installing this project's pinned `pydantic==2.10.4` globally
  broke the user's other packages (langchain, google-genai, scrapegraphai need >=2.12.5).
  The global environment was restored; never `pip install` this project globally.
- Three editable installs: `.` (service), `./langgraph_adf_adapter`, `./agperms`.
- Node 24.14.1 / npm 11.11.0 — dashboard deps installed, typecheck and build both clean.
- Docker 29.4.3 + Compose v5.1.4 available. `docker compose config -q` validates.
- Two primary gates now: `pytest -q` (service) and `pytest agperms/tests -q` (library).

## Current Active Feature
- None. F16 (`agperms`) is complete and passing.
- **WIP=1 applies.** Any follow-up work must set exactly one `not_started`/`blocked`
  feature in `features.md` to `active` before touching code. The only outstanding one is
  F13 (docker compose).

## Recently Completed
All sixteen features are `passing` except F13 (blocked) — see `features.md` for
per-feature verification and numbers. This session added F16:

- [x] **F16: `agperms` embeddable library** — `pip install agperms` gives an in-process
      `Firewall` with zero external dependencies. Answers the question the hosted service
      could not ("how do I use this in my project?"), since both prior installables
      assumed a running server.
- [x] **In-flight revocation forensics** — `fw.action(...)` context manager; a revoke now
      classifies open/failed actions as CLEAN/PARTIAL/UNKNOWN and queues non-CLEAN
      findings for human review, closed with a note written into the hash chain.
      Research confirmed no other *running* implementation does this — only the IETF draft
      `draft-sato-soos-mad-02` specifies it, with no code.
- [x] **Storage protocol + two backends** — `MemoryStorage` (default, no deps) and
      `SqlStorage` (`agperms[sql]`), both run against one conformance suite so the SQL
      path cannot drift from the in-memory one.
- [x] **No module-level singletons in the library** — the service's `db/session.py` and
      `db/redis_client.py` hold process-wide globals that make two instances clobber each
      other; the library takes all state by construction, pinned by a test.
- [x] **Executable README** — every documented example is a test. One of them caught a
      real doc bug: the intro example delegated a sensitive scope and would have raised.

Earlier sessions:
- [x] Checkpoint Service: root/delegate/verify/revoke/approve/deny + audit + admin
      endpoints, strict-subset enforcement, hash-chained audit log, durable revocation.
- [x] Eval harness, all 9 PRD items passing. 100% escalation block rate over 520
      parent/request combinations; revocation p95 1.69ms; engine verify p95 0.33ms.
- [x] LangGraph adapter as an installable package; verified against a real compiled
      `StateGraph`, and proven to block a node *before* its side effect runs.
- [x] React dashboard (4 screens, 2s polling), typechecks and builds clean.
- [x] Demo agents + `run_demo.py` executing all 7 PRD Section 11 steps, usable as a
      smoke test (non-zero exit if any security expectation fails).
- [x] Live Supabase + Upstash verification, which found three real deployment bugs.
- [x] Five AST-based architectural boundary checks, each with a meta-test proving the
      detector actually fires on a broken sample.
- [x] Four study-material documents in `Study Material/`.

## In Progress (Not Yet Verified)
- (nothing)

## Blocked
- **F13 (docker compose)** — never executed end to end; the user aborted the build. Only
  `docker compose config -q` has passed.

## Known Issues
<!-- Be specific. Vague issues help no one. -->
1. **`docker compose up` was never executed** (the user aborted the build). So the
   Layer-3 integration path is **unverified**: the containerised Postgres/Redis, the
   entrypoint's migration step, the healthchecks and the nginx dashboard image have not
   been exercised together. `docker compose config -q` passes and the live
   Supabase/Upstash run is real evidence the *code* works against hosted Postgres/Redis,
   but that is not the same claim. **Single biggest known gap.**
2. **`agperms` is not published to PyPI.** The name was confirmed available (404 on the
   PyPI JSON API); nothing has been uploaded. Publishing is irreversible and
   world-visible, so it needs an explicit decision.
3. **The service and the library are two implementations of the same rules.** Nothing
   keeps them in sync but their two test suites. Collapsing `checkpoint_service` onto
   `agperms` is the obvious follow-up and has not been done. Note this is a *duplication*
   problem, not a redundancy one — the service is still needed (see below).
4. **`agperms` is single-process.** Two `Firewall` instances over one shared store fork
   the audit hash chain — measured, and pinned by
   `test_two_instances_sharing_a_store_fork_the_chain`. Chain integrity needs one writer
   computing `prev_hash` from the current tail, enforced by a `threading.Lock` that cannot
   serialise across processes. This is why the service still exists; see DECISIONS.md
   2026-08-08 ("The Checkpoint Service is kept").
5. `agperms` in-memory storage is **not durable** — a restart resurrects revoked
   capabilities. Documented prominently; `SqlStorage` is the answer.
6. Checkpoints are **opt-in and manual** in the raw SDK. A forgotten `fw.action(...)`
   means a revoke has nothing to classify. The LangGraph guard closes this at node
   boundaries automatically.
7. A revoke **cannot interrupt** code already executing inside a `with fw.action(...)`
   block — nothing in-process can. Stated plainly in the README and the docstring: this
   buys knowledge, not prevention.
8. The primary gates run on SQLite + fakeredis / in-memory. Green tests do **not** prove
   the Postgres/Redis path. Any change to `models/`, `engine/revocation.py` or
   `db/session.py` needs the Layer-3 check above.
9. Latency numbers in `docs/results.md` are in-process. `docs/results-remote.md` has the
   network-inclusive figures (~250ms per backend round trip to Tokyo).
10. `.env` in the repo root contains **real generated secrets** from the live-backend
    session. It is gitignored, but exists on disk — rotate or delete if this directory is
    ever shared.
11. v1 admin auth is one shared static key with no per-human identity and no rotation
    flow beyond editing the env var and restarting. Documented as the weakest link.
12. `ADF_GUARDRAIL_EXEMPT_AGENTS` must be empty in production; an entry there is an
    unthrottled identity. The compose file sets it to `""` explicitly.
13. The audit hash chain is tamper-*evident*, not tamper-*proof*: unrestricted DB write
    access allows recomputing the chain from a chosen point forward. Mitigation
    (external notarisation of the tip) is documented, not implemented.
14. Exception messages in `action_failed` rows are truncated to 200 chars and land in an
    immutable log. Truncation bounds the blast radius; it does not sanitise.
15. `verify_success` audit rows are buffered in the *service* (not the library), so a hard
    crash can lose up to `ADF_AUDIT_BUFFER_MAX_SIZE` of them. Denials and mints are
    synchronous. Deliberate, documented trade — see DECISIONS.md.

## Settled Questions
<!-- Things a future session might otherwise re-litigate. -->
- **"Is the service still needed now that a library exists?" Yes.** Answered by
  measurement: two library instances sharing one store break the audit chain at row 3.
  Single process → library suffices. Multiple processes sharing one authority → the
  service is the single writer. Also required for non-Python agents, the approvals/tree
  UI, keeping the HS256 signing key off every verifier, and enforcing against an
  untrusted agent process. Full reasoning and rejected alternatives in DECISIONS.md
  2026-08-08.

## Next Steps
<!-- Ordered. The next session starts at item 1. -->
1. **Commit and push `agperms/`**, the `Study Material/` folder, and the updated docs.
   Nothing from this session is in git yet.
2. **Run the Layer-3 check** (Known Issue 1):
   `docker compose up -d --build`, then `curl -fsS http://localhost:8000/health`,
   then `python demo_agents/run_demo.py --admin-key $ADF_ADMIN_API_KEY`, then open the
   dashboard at http://localhost:8080. Fix anything that breaks and record the result
   in F13's evidence.
3. Decide on **publishing `agperms` to PyPI** (Known Issue 2). Needs a PyPI account and
   an explicit go-ahead; irreversible once uploaded.
4. Consider **collapsing the hosted service onto `agperms`** (Known Issue 3) so the two
   implementations of the same rules cannot drift.
5. Run the real load test against a live stack:
   `locust -f tests/locustfile.py --host http://localhost:8000 --headless -u 50 -r 10 -t 60s`
6. Optional hardening, in rough value order: RS256 + JWKS (removes the shared-secret
   verifier problem), OIDC admin auth (gives `approved_by` a real identity), external
   notarisation of the audit chain tip.

## Decisions Made This Session
<!-- Summary — full detail in DECISIONS.md -->
Five new entries (2026-08-08), on top of the fourteen from earlier sessions:

- **`agperms` extracted as an embeddable library** with storage behind one protocol. The
  existing service could not simply be imported: `db/session.py` and `db/redis_client.py`
  hold process-wide mutable globals, so two instances clobber each other.
- **One unit-atomic storage protocol, not two transaction lifecycles.** The service mixes
  session-per-call with a self-owning transaction in `AuditLogger`; an in-memory backend
  cannot implement both coherently.
- **In-flight action checkpointing** — the genuine gap after researching six competing
  projects (`adk-agentmesh`, `wafers`, `warden`, `ScopeGate`, `MiniScope`, `legant`) and
  the IETF drafts. `UNKNOWN` is never treated as `CLEAN` (INV-15), pinned by a
  pure-function test.
- **Checkpoints are forensic, not preventive** — documented explicitly, because letting a
  reader believe otherwise would stop them building the thing that actually protects them.
- **Failure reasons truncated to 200 chars; review notes go in the hash chain**, not a
  mutable column, so the conclusion and the evidence can be cross-checked.

---
<!-- AGENT REMINDER:
  - "In Progress" ≠ "Done". Only move to Completed after verification passes.
  - If pytest is FAILING when you write this, say so honestly.
  - The next session will trust this file. Make it trustworthy.
-->
