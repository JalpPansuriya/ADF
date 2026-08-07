# HARNESS_ENGINEERING.md
# ========================
# Complete harness engineering reference for AI coding agents.
# AGENT: Read this when you need to understand WHY a rule exists,
# or when AGENTS.md doesn't answer your question.

---

## Core Principle

> **When things fail, fix the harness first — not the model.**

Model capability and execution reliability are two different things.
The same model in a bare environment vs. a complete harness produces
fundamentally different output. Every failure is a signal that your
harness has a structural defect. Find it and fix it.

---

## Part 1 — What a Harness Is

A harness = everything in the engineering infrastructure outside the model weights.

It has five subsystems. ALL five are required. Missing any one = incomplete harness.

### The Five Subsystems

| # | Subsystem | What it does | Key artifact |
|---|-----------|-------------|-------------|
| 1 | **Instructions** | Tells the agent what the project is, how to run it, and what the hard rules are | `AGENTS.md`, topic docs |
| 2 | **Tools** | Gives the agent the capabilities it needs (shell, files, tests) | Shell access, test runner |
| 3 | **Environment** | Makes the runtime state self-describing and reproducible | `pyproject.toml`, `docker-compose.yml`, `.env.example` |
| 4 | **State** | Lets a new session pick up where the last one left off | `PROGRESS.md`, `DECISIONS.md`, git commits |
| 5 | **Feedback** | Tells the agent objectively whether it succeeded | Verification commands, test results |

**Diagnostic question for every failure**: Which of the five subsystems was missing or broken?

### The Five Failure Modes (Map every bug to one)
1. **Vague requirements** → Task specification subsystem failure
2. **Implicit conventions not written down** → Instructions subsystem failure
3. **Incomplete environment setup** → Environment subsystem failure
4. **No verification methods** → Feedback subsystem failure
5. **Cross-session state loss** → State subsystem failure

---

## Part 2 — The Repository as Single Source of Truth

### The Rule
**If it's not in the repo, it doesn't exist for the agent.**

The agent has exactly three input sources:
- System prompts and task descriptions
- File contents from the repository
- Tool execution output

Slack history, Jira tickets, Confluence pages, and what's in an engineer's head:
the agent cannot see any of it.

### The Fresh Session Test
Open a brand-new agent session. Show it only repo contents. Can it answer these?

| Question | Where the answer should live |
|----------|------------------------------|
| What is this system? | `AGENTS.md` / `README.md` |
| How is it organized? | `README.md` architecture section / `docs/PRD.md` §4 |
| How do I run it? | `AGENTS.md` Quick Start |
| How do I verify it? | `AGENTS.md` verification commands |
| Where are we now? | `PROGRESS.md` / `features.md` |
| Why does X deviate from the spec? | `DECISIONS.md` |

If any answer is missing, the map has blank spots.
Blank spots = guesses. Wrong guesses = bugs. Repeated guesses = wasted context.

### Knowledge Placement Rules
1. **Near code**: Rules about a module go in that module's docstring, not a global doc.
2. **Minimal but complete**: Every piece of knowledge has a clear use case. Remove anything unused.
3. **Update with code**: Doc changes are committed together with code changes.
4. **MUST / MUST NOT language**: Hard constraints use explicit language, not suggestions.

### ACID State Management
Apply database transaction principles to agent state:

| Principle | Meaning for agents |
|-----------|-------------------|
| **Atomicity** | Each logical operation = one git commit. All or nothing. |
| **Consistency** | After any operation, the primary gate passes. No partial states committed. |
| **Isolation** | Concurrent agents use separate progress files or git branches. |
| **Durability** | Critical cross-session knowledge lives in git-tracked files. Not in your head. |

---

## Part 3 — Instruction Architecture

### The Golden Rule: Entry File = Router, Not Encyclopedia

`AGENTS.md` target size: **50–200 lines**.
It contains: project overview + quick start + hard constraints + links to topic docs.
It does NOT contain: all the rules, all the history, all the notes.

### Why Bloated Instruction Files Fail
- **Context budget drain**: A 600-line `AGENTS.md` can consume 10–20K tokens, leaving less budget for reading actual code.
- **Lost in the Middle**: LLMs use information at the start and end of long texts far more reliably than the middle. A critical rule at line 300 of 600 will often be ignored.
- **Priority confusion**: When hard constraints, design guidelines, and historical notes all look identical, the agent can't tell what's non-negotiable.
- **Maintenance decay**: Files only grow, never shrink. Signal-to-noise ratio falls continuously.

### Instruction Architecture Pattern
```
AGENTS.md (50–200 lines)
├── Project overview (2–3 sentences)
├── Quick start commands
├── Hard constraints (≤ 15 rules, non-negotiable)
└── Links to topic docs with applicability conditions

docs/ + agent-files/
├── PRD.md                (read when: you need the product spec / API contract)
├── DECISIONS.md          (read when: unsure why something exists or deviates)
├── features.md           (read when: choosing what to work on)
├── results.md            (read when: you need measured eval numbers)
└── HARNESS_ENGINEERING.md (read when: confused about a harness rule)
```

### The Vicious Cycle to Avoid
"Agent makes mistake → add a rule to AGENTS.md → works temporarily → agent makes different mistake → add another rule → file bloats → performance degrades."

**Break the cycle**: Before adding a rule to the entry file, ask:
- Does this belong in a topic doc instead?
- Does an existing topic doc need updating?
- Should this be a test or a grep check instead of prose?

### Instruction Audit (Do monthly)
Every instruction entry should have:
- **Source**: Why was this rule added?
- **Applicability**: When does it apply?
- **Expiry**: Under what conditions can it be removed?

Delete outdated, redundant, and contradictory entries. Treat instruction debt like technical debt.

---

## Part 4 — Cross-Session State Persistence

### Why Sessions Lose Context
Context windows are finite. Long tasks WILL span sessions. When a session ends:
- All intermediate reasoning ("why option A over B") is lost
- Only the final code ("what") survives
- The next session sees code but doesn't know why it's written that way

### Context Anxiety
When agents sense context is running low, they exhibit "rushed finish" behavior:
- Skip verification steps
- Choose simple solutions over optimal ones
- Declare completion early

**Solution**: Use structured state files so new sessions start clean, without anxiety.

### The Four State Persistence Artifacts

**1. PROGRESS.md** — What happened, what's next
```markdown
## Current State
- Latest commit: abc1234
- Test status: 42/43 passing (test_X failing — reason: Y)

## Completed
- [x] Feature: description (verified, commit abc123)

## In Progress
- [ ] Feature: description (X% complete, current blocker: Y)

## Known Issues
- Issue description (impact, workaround if any)

## Next Steps
1. Specific next action
2. Next action after that
```

**2. DECISIONS.md** — Why things were built a certain way
```markdown
## YYYY-MM-DD: Decision title
- Reason: Why this approach
- Rejected alternative: What else was considered and why rejected
- Constraint: Any rule this decision creates going forward
```

**3. Git commits as checkpoints**
- Commit after every atomic unit of verified work
- Commit message = what was done + why
- Never commit broken state

**4. Session clock-in / clock-out ritual** (defined in `AGENTS.md`)

### Clock-In (start of every session)
1. Read `PROGRESS.md`
2. Read `features.md`
3. Run the primary gate — if red, fix before new work
4. Continue from "Next Steps"

### Clock-Out (end of every session)
1. Update `PROGRESS.md`
2. Run the primary gate
3. Commit all verified work
4. Remove debug/temp artifacts

### Compaction vs. Reset
| Strategy | Use when | Risk |
|----------|----------|------|
| **Compaction** (summarize in-session) | Task is < 60% of context window | Loses "why" decisions |
| **Context reset** (new session + artifacts) | Task exceeds 60% of window | Requires complete handoff artifacts |

Rule of thumb: If a task will exceed 60% of context, prepare handoff artifacts proactively, don't wait until context is almost full.

---

## Part 5 — Task Scope and WIP Control

### The Core Problem
Agents have an impulse to "do a little extra." They see related things and handle them along the way. Every additional modification dilutes attention. Attention is finite.

**Mathematical reality**: If context capacity is C and agent activates k tasks simultaneously, each task gets C/k reasoning resources. When C/k drops below the minimum threshold to complete one task, none of them finish.

### WIP=1 Rule
**Only ONE feature may be in `active` state at any time.**

In `AGENTS.md`:
```
## Work Rules
- Work on ONE feature at a time (WIP=1)
- Do NOT start feature B until feature A passes end-to-end verification
- Do NOT refactor unrelated code while implementing a feature
```

### Completion Evidence
Every feature entry MUST have an executable verification command.

**Wrong** (subjective): "Delegation is secure"
**Right** (executable): `pytest tests/test_delegation_rules.py -q` returns 0 failures

"Done" = verification command executes and passes. Not "code is written." Not "looks correct."

### Scope Surface (features.md format)
```json
{
  "id": "F04",
  "behavior": "POST /tokens/delegate returns 403 scope_escalation_denied for any superset request",
  "verification": "pytest tests/test_delegation_rules.py -q",
  "state": "not_started",
  "evidence": null
}
```

States: `not_started` → `active` → `passing` (or `blocked`)
- Only ONE feature `active` at a time
- Agent CANNOT self-promote to `passing` — verification command must pass
- `passing` is irreversible

### Overreach Warning Signs
- More than 1 feature in `active` state
- Code changes spanning > 5 unrelated files
- "I'll also fix this while I'm here" thinking
- Tests written but none passing end-to-end

---

## Part 6 — Preventing Premature Completion

### The Core Problem
Agents are systematically overconfident. Neural networks report higher confidence than their actual accuracy. "The code looks fine" is not evidence of correctness.

**Confidence calibration bias**: Agent self-reported completion confidence is consistently higher than actual completion quality, especially on complex multi-file tasks.

### Three-Layer Termination Validation

Every task must pass all three layers. No shortcuts. No skipping.

```
Layer 1: Syntax + Static Analysis
  ├── Package imports cleanly (python -c "import checkpoint_service.main")
  ├── Dashboard typechecks (npx tsc --noEmit)
  └── Build succeeds (npm run build)

Layer 2: Runtime Behavior
  ├── Unit tests pass (pytest tests/test_token_engine.py etc.)
  ├── API contract tests pass (pytest tests/test_api_contract.py)
  └── Service starts successfully (uvicorn boots, /health responds)

Layer 3: System-Level Confirmation
  ├── End-to-end demo executes (demo_agents/run_demo.py, all 7 steps)
  ├── Critical security paths verified (escalation blocked, revocation propagates)
  └── Side effects confirmed (audit rows written, hash chain intact, edges persisted)
```

**Cross-component changes require Layer 3.**
**Do not proceed to Layer 2 if Layer 1 fails.**
**Do not proceed to Layer 3 if Layer 2 fails.**

### Why Unit Tests Alone Are Not Enough

Unit tests are designed to isolate. This isolation is precisely what makes them blind to:
- **Interface mismatches**: Engine returns a `MintedToken`; route expects a raw string. Both unit tests pass using mocks.
- **State propagation errors**: A revocation lands in Redis but not Postgres; a restart resurrects the token. Never visible in a single-process unit test.
- **Resource lifecycle issues**: The audit buffer's background task is never flushed, so assertions read a table that is still empty.
- **Environment dependencies**: SQLite accepts a schema that Postgres rejects (or vice versa).

### No Refactoring Until Core Functionality Is Verified
The completion priority constraint:
1. First: verify functional correctness
2. Then: address performance
3. Finally: handle style

Refactoring before verification is forbidden. It moves the boundary between verified and unverified code.

### Separate Worker from Checker
The model that generates code cannot objectively evaluate its own work. It will systematically be too lenient with itself.

For high-stakes tasks, use a separate evaluator prompt/agent that:
- Is explicitly instructed to be critical
- Uses a scoring rubric (not "does it feel right?")
- Cites specific evidence for every judgment
- Cannot be talked out of failures

### Agent-Oriented Error Messages
When verification fails, error messages should include three elements:
```
WHAT: [exactly what failed, with file and line number]
WHY:  [why this is wrong, what rule it violates]
FIX:  [concrete steps to fix it]
```

---

## Part 7 — End-to-End Testing and Architectural Boundaries

### Why Only a Full Pipeline Run Counts
Component boundary defects only surface when everything runs together. Five categories unit tests always miss:
1. Interface mismatches between components
2. State propagation errors across layers
3. Resource lifecycle issues spanning components
4. Environment dependency failures
5. Error propagation failures across boundaries

### Architectural Boundary Rules
Architecture constraints must be **executable**, not written in documents.

Every architectural rule should have a corresponding automated check:
```bash
# Unverified token decoding must never appear on the enforcement path
grep -rn "decode_unverified" checkpoint_service/engine/delegation_engine.py \
  checkpoint_service/routes/tokens.py && exit 1 || echo OK

# Postgres-specific types must not enter the models (breaks the SQLite test path)
grep -rn "JSONB\|postgresql\." checkpoint_service/models/ && exit 1 || echo OK

# Admin key comparison must be constant-time
grep -rn "admin_api_key ==" checkpoint_service/ && exit 1 || echo OK
```

Rules written in documents but not enforced by checks will be violated by agents — not maliciously, but because agents copy patterns they see in the repo.

### Review Feedback Promotion
Every time a recurring violation is found in code review:
1. Identify the pattern
2. Write an automated check for it
3. Add an agent-oriented error message
4. Add the check to the primary gate
5. The harness is now permanently stronger against this failure

---

## Part 8 — Observability

### Why Observability Matters
Without it:
- Cannot distinguish "correct" from "looks correct"
- Evaluation becomes subjective judgment
- Retries become blind guessing
- New sessions spend 30–50% of time on redundant diagnosis

### Two Observability Layers

**Runtime observability** (system layer):
- Application lifecycle events (startup, ready, shutdown)
- Feature path execution records
- Data flow between components
- Resource utilization patterns
- Full error context

**Process observability** (harness layer):
- Sprint contracts (scope + verification standards + exclusions)
- Evaluator rubrics (structured scoring, not "feels right")
- Task traces (full decision path from start to completion)

### Sprint Contract (negotiate before coding begins)
```markdown
# Sprint Contract: [Feature Name]

## Scope
- [Specific files/components to change]
- [What will NOT be touched]

## Verification Standards
- [Specific test commands that must pass]
- [End-to-end scenarios that must work]

## Exclusions
- [What is explicitly out of scope]
- [Known limitations acceptable for this sprint]
```

### Evaluator Rubric (structured scoring)
```
| Dimension          | A (Pass)          | B                  | C                 | D (Fail)     |
|--------------------|-------------------|--------------------|-------------------|--------------|
| Code correctness   | All tests pass    | Main flow passes   | Partial pass      | Build fails  |
| Architecture       | Fully compliant   | Minor deviations   | Obvious deviations| Violations   |
| Test coverage      | Main + edge cases | Main flow only     | Skeleton only     | No tests     |
| E2E verification   | All paths pass    | Happy path passes  | Partial           | Not run      |
```

Score each dimension independently. Cite specific evidence. Never approve based on vague impressions.

---

## Part 9 — Clean Session Exit

### Why Clean Exit Is Non-Negotiable
Entropy growth is the default state of any codebase under continuous change.
Agents copy patterns they see — including bad ones.
"I'll clean up later" = never cleaning up. The next session has new objectives and won't clean up your mess.

### Five Dimensions of Clean State
All five must be satisfied before a session is "done":

| Dimension | Requirement |
|-----------|-------------|
| **Build** | Package imports; dashboard `npm run build` succeeds with zero errors |
| **Tests** | ALL tests pass — including tests that existed before this session |
| **Progress** | `PROGRESS.md` updated: completed, in-progress, blocked, next steps |
| **Artifacts** | No debug code, no stray `print()`, no `breakpoint()`, no temp files, no commented-out blocks, no `TODO` without an owner |
| **Startup** | Standard startup path works; next session can begin without manual intervention |

### Session Exit Checklist (run before every session end)
```bash
pytest -q               # Must be green
# Then manually verify:
# [ ] PROGRESS.md updated
# [ ] features.md states updated
# [ ] git commit with descriptive message
# [ ] No stale artifacts
```

### Cleanup Strategy: Two Modes

**Immediate cleanup** (every session):
- Remove temp artifacts from this session
- Update feature and progress files
- Ensure the primary gate is green
- Commit verified work

**Periodic cleanup** (weekly):
- Full-system scan for accumulated drift
- Update quality document (score each module)
- Run benchmark tasks to detect harness degradation
- Remove harness components that are no longer needed

### Quality Document Pattern
```markdown
# Quality Document

## [Module Name] — Quality: A/B/C/D
- Verification passing: Yes / No / Partial
- Agent understandable: Yes / Difficult
- Test stability: Stable / Unstable (N flaky tests)
- Architecture boundaries: Compliant / Violations present
- Code conventions: Followed / Partially / Not followed
- Notes: [specific issues]
```

Grade each module monthly. Fix lowest-scoring modules first.

### Harness Simplification
As model capabilities improve, periodically remove harness constraints that are no longer necessary.

Monthly practice: pick one harness component, disable it, run benchmark tasks. If results don't degrade — remove it. If they do — restore it.

**The agent engineer's job is to continuously find the next valuable harness combination, not maintain every constraint forever.**

---

## Quick Reference: Diagnostic Loop

When a task fails, run through this before concluding "the model isn't good enough":

```
1. Was the task description clear and specific?
   → If not: Task specification failure (Instructions subsystem)

2. Did the agent have access to all necessary project context?
   → If not: Knowledge visibility failure (Instructions / State subsystem)

3. Was the environment set up correctly? Dependencies, versions, services?
   → If not: Environment subsystem failure

4. Were there verification commands the agent could run?
   → If not: Feedback subsystem failure

5. Did a previous session leave the repo in a broken/ambiguous state?
   → If yes: State management failure

6. Did the agent declare completion without running end-to-end verification?
   → If yes: Premature completion declaration (Verification gap)

7. Did the agent work on multiple features simultaneously?
   → If yes: WIP > 1 violation (Scope control failure)
```

Only after all 7 are checked and cleared should you consider the model itself as the bottleneck.

---

## Benchmark Numbers (Reference)

| Metric | Without harness | With full harness |
|--------|----------------|-------------------|
| Task success rate (simple) | 20% | 80–100% |
| New session rebuild time | 15–20 min | 3–5 min |
| Security constraint compliance | 60% | 95% |
| Feature completion (multi-session) | 58% | 100% |
| Week 12 build pass rate | 68% | 97% |
| Week 12 test pass rate | 61% | 95% |
| Verified completion rate (WIP=1 vs unconstrained) | 37.5% | 87.5% |

These numbers come from controlled experiments using the same model, same task, different harness quality.

---

## Part 10 — ADF Harness Configuration

### Project-Specific Environment
| Artifact | ADF Implementation |
|----------|-------------------|
| **Instructions** | `agent-files/AGENTS.md` (entry) + `docs/PRD.md` (spec) + `agent-files/DECISIONS.md` (ADRs) |
| **Tools** | Shell (PowerShell), file read/write, pytest, pip, npm, docker compose |
| **Environment** | `pyproject.toml` (pinned deps), `.env.example` (all `ADF_*` vars), `docker-compose.yml` (api/redis/postgres/dashboard), `sensitive_scopes.yaml` (approval policy) |
| **State** | `agent-files/PROGRESS.md` + `features.md` + `DECISIONS.md` + git commits |
| **Feedback** | `pytest -q` (primary gate, 9 eval items), `docs/results.md` (measured numbers), `/audit/verify_integrity` (runtime self-check) |

### Why This Project Needs an Unusually Strong Feedback Subsystem
ADF is a security control. A security control that is subtly broken is worse than one that
is absent, because it produces false confidence. "The subset check looks right" is not
evidence; a parametrized test that attempts every superset combination and observes a 100%
block rate is. This is why eval item 1 is parametrized rather than a single happy-path
assertion, and why item 9 asserts the *absence of a side effect* rather than the presence
of an exception.

### ADF Five Failure Modes
| # | Failure Mode | ADF Example | Fix |
|---|-------------|-------------|-----|
| 1 | Vague requirements | "Enforce delegation properly" | Rewrite as: "`requested ⊄ parent.scopes` → 403 with `denied_scopes` listing exactly the offending scopes" |
| 2 | Implicit conventions | Agent puts a raw `human_id` in a JWT claim because PRD §5's example does | Hard Constraint 5 + DECISIONS entry on opaque subjects; `SubjectRegistry` is the only way to produce a subject id |
| 3 | Incomplete environment | Missing `ADF_JWT_SECRET`, service boots with an empty signing key | `Settings.validate_secrets()` refuses to boot; there is no default |
| 4 | No verification | "Revocation propagates instantly" with nothing measured | `tests/test_revocation.py` builds a 3-level chain, revokes the root, and prints the measured propagation latency |
| 5 | Cross-session state loss | A later session "fixes" the verify order back to the PRD's pseudocode, reintroducing the unverified-claim read | DECISIONS.md 2026-08-07 (verify order) + a grep check in AGENTS.md |

### ADF Verification Strategy
```
Layer 1: Static
  ├── python -c "import checkpoint_service.main"
  └── cd dashboard && npx tsc --noEmit && npm run build

Layer 2: Runtime
  └── pytest -q   (all 9 eval items + unit tests, SQLite + fakeredis)

Layer 3: System-level
  ├── docker compose up --build   (real Postgres + real Redis)
  ├── python demo_agents/run_demo.py   (PRD §11, all 7 steps)
  └── GET /audit/verify_integrity → intact
```
Note the asymmetry: Layer 2 runs on SQLite + fakeredis and is fast enough to run every
session, but it does **not** prove the Postgres/Redis path works. Any change to
`models/`, `revocation.py`, or `session.py` requires Layer 3 before being called done.

### ADF Architectural Boundaries
| Boundary | Rule | Enforcement |
|----------|------|-------------|
| Caller ↔ Token Engine | Signature verified before any claim is read | `grep -rn "decode_unverified"` must not match the engine or routes |
| Engine ↔ Revocation | Postgres is the source of truth; Redis is a cache | `RevocationStore` is the only writer; `tests/test_revocation.py::test_revocation_survives_cache_loss` |
| Engine ↔ Audit | Append-only, single writer, hash-chained | No `UPDATE`/`DELETE` on `audit_log` in service code; `/audit/verify_integrity` |
| Models ↔ Backends | Backend-neutral column types only | `grep -rn "JSONB" checkpoint_service/models/` must not match |
| Approval ↔ Minting | No JWT exists while a request is pending | `tests/test_approval_gate.py` asserts no token is returned on 202 |
| Dashboard ↔ API | Read-only except approve/deny and break-glass reset | Dashboard has no admin key except where explicitly configured |

### ADF ACID State Management
| Principle | ADF Application |
|-----------|----------------|
| **Atomicity** | Each feature (F01–F14) = one commit. A subtree revocation is one DB transaction. |
| **Consistency** | `pytest -q` green after every change. The hash chain is verifiable at any point. |
| **Isolation** | Single-writer audit logger serializes chain appends; WIP=1 for features. |
| **Durability** | Revocations and mints committed to Postgres before the caller is told the outcome. |

### Agent-Oriented Error Messages for ADF
```
WHAT: ConfigurationError at startup — "ADF_JWT_SECRET still looks like a placeholder"
WHY:  Hard Constraint 6. A guessable HS256 secret lets anyone forge a token with any
      scope set, which voids every other guarantee in the system.
FIX:  Copy .env.example to .env and generate real values:
      python -c "import secrets; print(secrets.token_urlsafe(48))"

WHAT: pytest tests/test_delegation_rules.py fails — a superset request returned 201
WHY:  Hard Constraint 2 violated. The child received a scope its parent did not hold,
      which is the exact escalation this service exists to prevent.
FIX:  Check DelegationEngine.delegate() computes `denied` against the *live decoded
      parent token's* scopes, not against the requested list or a cached record.

WHAT: A test asserts on an audit row and finds the table empty
WHY:  verify_success events are buffered by the single background writer
      (DECISIONS.md 2026-08-07). The row is not durable yet at assertion time.
FIX:  Call AuditLogger.flush() (or the app's flush hook) before querying audit_log.

WHAT: Revoked token verifies as valid after restarting Redis
WHY:  Hard Constraint 3 violated — revocation state was written only to the cache.
FIX:  Route the write through RevocationStore.revoke_subtree(), which commits to
      Postgres first, and confirm rebuild_cache() runs in the app's startup hook.

WHAT: sqlalchemy.exc.CompileError / OperationalError only under pytest
WHY:  A Postgres-specific column type (e.g. JSONB) entered models/, which SQLite
      cannot compile. Breaks the primary gate.
FIX:  Use JSON instead of JSONB, String instead of UUID (Hard Constraint 9).
```

---
*Sources: Anthropic "Effective Harnesses for Long-Running Agents", OpenAI "Harness Engineering: Leveraging Codex in an Agent-First World", Liu et al. "Lost in the Middle" (2023), Guo et al. "On Calibration of Modern Neural Networks" (2017)*
