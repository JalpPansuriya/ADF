# AGENTS.md — Project Harness Entry File
# =========================================
# AGENT: Read this file COMPLETELY before touching any code.
# This is your single source of truth. If it's not here, it doesn't exist.

## Project Overview
**Agent Delegation Firewall (ADF)** is a framework-agnostic authorization service for
multi-agent AI pipelines. It mints, verifies, narrows and revokes cryptographic
capability tokens so a child agent can **never** hold more scope than its parent held at
delegation time. Components: a FastAPI Checkpoint Service (JWT/PyJWT, Postgres audit log,
Redis cache), a LangGraph adapter package, a React dashboard, and a pytest eval harness.

## Quick Start Commands
```bash
# Install (editable, with dev extras) — run from repo root
pip install -e ".[dev]"
pip install -e ./langgraph_adf_adapter
pip install -e ./agperms

# PRIMARY GATE: both suites must be green
pytest -q                    # hosted service: 848 tests (SQLite + fakeredis)
pytest agperms/tests -q      # embeddable library: 366 tests (memory + SQL)

# Architectural boundary checks (AST-based)
python -m tests.check_boundaries

# Regenerate docs/results.md with real measured numbers
python -m tests.generate_results

# Full stack (api + redis + postgres + dashboard)
docker compose up --build

# Scripted end-to-end demo (PRD Section 11) against a running stack
python demo_agents/run_demo.py

# Dashboard dev server (expects API on :8000)
cd dashboard && npm install && npm run dev
```
<!-- AGENT: Run `pytest -q` at the START of every session to confirm the suite is green. -->
<!-- AGENT: Run `pytest -q` at the END of every session before declaring anything "done". -->

## Hard Constraints
<!-- Non-negotiable. Violating any of these is a blocking error, not a suggestion. -->

1. **Never trust an unverified claim**: `TokenEngine.decode()` (signature check) MUST run
   before any claim — including `jti` — is read. `decode_unverified()` is banned from the
   enforcement path. This deviates from the PRD Section 7 pseudocode deliberately.
2. **Strict subset, always**: `child.scopes ⊆ parent.scopes` (equal allowed, exceeding
   never). No code path may mint a child with a scope absent from the live parent token.
3. **Revocation fails CLOSED**: Postgres is the source of truth for revocations and
   delegation edges; Redis is a read cache only. Losing Redis must never make a revoked
   token valid again.
4. **No token exists while approval is pending**: sensitive-scope delegations return
   `202` and persist a `PendingApproval` row. The JWT is minted only inside the approve
   handler. Never mint-then-mark.
5. **No secrets in tokens or logs**: tokens carry opaque `human:<uuid>` / `agent:<uuid>`
   subjects only. Raw human identifiers are persisted **only** as `sha256(id + salt)` in
   `audit_log.actor_hash`; the reverse mapping lives in `subject_map`.
6. **No insecure defaults**: the service MUST refuse to boot if `ADF_ADMIN_API_KEY`,
   `ADF_JWT_SECRET` or `ADF_PII_SALT` are missing, short, or placeholder values.
7. **Audit log is append-only and hash-chained**: never `UPDATE` or `DELETE` an
   `audit_log` row in service code. Writes go through `AuditLogger` only (single writer,
   so the chain cannot interleave).
8. **Admin key comparison is constant-time**: use `secrets.compare_digest`, never `==`.
9. **Backend-portable SQL**: models must work on both SQLite (test harness) and Postgres
   (production). Use `JSON`, not `JSONB`; `String`, not `UUID`.
10. **One task at a time**: WIP=1. Do NOT start a new feature until the current one's
    verification command passes.
11. **No premature completion**: "Done" = verification command passed. "Code is written"
    is NOT done.
12. **Clean exit**: before ending a session, update PROGRESS.md + features.md, run
    `pytest -q`, remove debug/temp artifacts.
13. **No refactoring while implementing**: do not refactor unrelated code during a
    feature session.

## Verification Commands (Copy-paste ready)
```bash
# Primary gate — the whole eval harness (PRD Section 10, items 1-9)
pytest -q

# Per-eval-item targets
pytest tests/test_delegation_rules.py -q     # items 1, 2
pytest tests/test_revocation.py -q           # item 3
pytest tests/test_audit_chain.py -q          # item 4
pytest tests/test_circuit_breaker.py -q      # item 5
pytest tests/test_audit_integrity.py -q      # item 6
pytest tests/test_approval_gate.py -q        # item 7
pytest tests/test_load_verify.py -q          # item 8 (latency, prints p50/p95)
pytest tests/test_langgraph_adapter.py -q    # item 9

# Import/compile check for the whole service package
python -c "import checkpoint_service.main"

# Dashboard typecheck + build
cd dashboard && npx tsc --noEmit && npm run build

# Architectural boundary checks (AST-based, enforce the Hard Constraints above).
# Also run as tests/test_boundaries.py inside the primary gate.
python -m tests.check_boundaries
```

## Feature List (Source of Truth for What's Built)
<!-- AGENT: Read features.md for current task state. Do NOT rely on conversation history. -->
**Feature list location**: `agent-files/features.md`
**Format**: Each feature has: behavior description + verification command + state
(not_started / active / blocked / passing)
**Rules**:
- Only ONE feature may be in `active` state at a time.
- You CANNOT change a feature to `passing` yourself. Run its verification command; the
  result decides.
- Pick the next `not_started` feature in order. Do not skip.

## Current Progress
<!-- AGENT: Read PROGRESS.md for current session state. -->
**Progress file**: `agent-files/PROGRESS.md`
**Read it at session start. Update it at session end. Always.**

## Topic Documents (Read on demand — only when relevant)
| Document | Read when... |
|----------|-------------|
| `docs/PRD.md` | You need the original product spec and API contract |
| `agent-files/DECISIONS.md` | Unsure why something was built a certain way, or why it deviates from the PRD |
| `agent-files/features.md` | Need task-level state |
| `docs/results.md` | Need the measured eval numbers |
| `agent-files/HARNESS_ENGINEERING.md` | Confused about any harness rule or concept |
| `README.md` | Need the threat model / architecture / upgrade paths |

## Session Startup Ritual (Do this EVERY session, in order)
```
1. Read agent-files/PROGRESS.md — understand current state
2. Read agent-files/features.md — know which feature is active
3. Run `pytest -q` — confirm the suite is green
4. If tests fail: fix them BEFORE doing any new work
5. Continue from PROGRESS.md "Next Steps" section
```

## Session Exit Checklist (Complete EVERY item before ending)
```
[ ] pytest -q passes (zero failures)
[ ] docs/results.md regenerated if eval behaviour changed
[ ] PROGRESS.md updated (completed, in-progress, blocked, next steps)
[ ] features.md states updated with real evidence (test output, not prose)
[ ] No debug code left (print(), breakpoint(), console.log, TODO without an owner)
[ ] No half-finished features left in an unverifiable state
```

## Definition of Done
A feature is DONE when and only when:
1. `pytest -q` passes with zero failures
2. All pre-existing functionality still works
3. PROGRESS.md and features.md are updated to reflect `passing`, with command output as
   evidence

**"The code looks fine" is NOT done. "The verification command passed" IS done.**

---
*For full harness engineering principles, see: `agent-files/HARNESS_ENGINEERING.md`*
