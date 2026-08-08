# DECISIONS.md
# =============
# AGENT: Read this when you're unsure WHY something was built a certain way.
# AGENT: Add an entry whenever you make a non-obvious architectural or technical decision.
# AGENT: This prevents future sessions from "optimizing away" intentional choices.

## Format
Each entry answers: What was decided? Why? What was rejected and why? What constraint
does it create going forward?

**Special note for this project**: several entries below record *deliberate deviations
from `docs/PRD.md`*. The PRD is the product spec, not the implementation authority. Where
the PRD is internally contradictory or specifies something unsafe, this file records the
resolution. Do not "fix" the code back to the PRD without reading the relevant entry.

---

## 2026-08-07: Verify order — signature before any claim is read (DEVIATES FROM PRD 7)
**Decision**: `/verify` evaluates in this order: circuit breaker → **signature** → expiry
→ revocation → required scope. The PRD's pseudocode checks `is_revoked(token.jti)` first.
**Reason**: `token.jti` is a *claim*. Reading it before verifying the signature means
trusting attacker-controlled bytes. An attacker could submit an unsigned token whose `jti`
is any value they like; the revocation lookup would then be answering a question about a
token that was never issued. Signature verification must gate all claim access. The
circuit-breaker check runs first only because it reads nothing from the token at all.
**Rejected alternative**: Follow the PRD literally — rejected as a security defect.
**Constraint created**: `decode_unverified()` exists for dashboard/diagnostic rendering
only and MUST NOT appear in `delegation_engine.py` or `routes/tokens.py`. There is a grep
check for this in AGENTS.md.

---

## 2026-08-07: Revocation durability — Postgres is source of truth, Redis is a cache (DEVIATES FROM PRD 8.4)
**Decision**: Revoked jtis and parent→child delegation edges are written to Postgres
(`revocation`, `delegation_edge`) inside the same transaction as the revoke request. Redis
holds a mirror for O(1) reads and is **rebuilt from Postgres at startup**. If Redis is
unavailable, `is_revoked()` falls back to a Postgres query (slower, still correct).
**Reason**: The PRD stores revocation state solely in Redis. Redis without persistence
loses its keyspace on restart; with AOF it can still lose the tail of the log. Either way
the failure mode is **fail-open** — a revoked token silently becomes valid again. That
inverts the system's headline guarantee ("revoking a root token invalidates its entire
downstream subtree"), which is the single most security-critical behaviour here.
**Rejected alternative**: (1) Redis with `appendonly yes` — rejected because durability
would depend on container config rather than application logic, and AOF still has a lossy
tail. (2) Redis-only with the limitation documented — rejected because a documented
fail-open is still a fail-open.
**Constraint created**: Never write a revocation to Redis without also committing it to
Postgres. Any new revocation code path must go through
`RevocationStore.revoke_subtree()`. Redis MUST remain optional for correctness.

---

## 2026-08-07: Approval gate mints on approval; no token exists while pending (RESOLVES PRD 5/7 CONTRADICTION)
**Decision**: A delegation requesting a sensitive scope returns `202` with an
`approval_id` and persists a `pending_approval` row. **No JWT is minted.** The human calls
`POST /tokens/approve`, which is where the child token is minted (clamped to the parent's
`exp` recorded at request time). The delegating agent then collects it once via
`GET /tokens/pending/{approval_id}`. `POST /tokens/deny` marks the request denied and
mints nothing, ever.
**Reason**: The PRD is self-contradictory here. Section 5 rule 6 and the Section 7
pseudocode say block minting until approved, but the Section 5 token schema carries
`approval_required` / `approved_by` claims, which only make sense if a token was already
minted and then annotated. Mint-then-mark puts a validly signed token in circulation whose
safety depends entirely on every future verifier remembering to check a side table — a
fail-open design. Mint-on-approval means an unapproved capability has no representation
that could ever be replayed. The schema claims are retained and populated at mint time so
an approved token still records who approved it.
**Rejected alternative**: Mint immediately with `approval_required=true` and reject at
verify — rejected because it depends on verifier discipline rather than the absence of a
credential.
**Constraint created**: `mint_child()` may be called from the delegate handler only for
non-sensitive scopes, and from the approve handler for approved ones. Never add a code
path that mints a token with `approval_required=True and approved_by is None`.
The parent's `exp` ceiling MUST be read from the stored `pending_approval.parent_exp`, not
recomputed at approval time, or a slow approval could extend a child beyond its parent.

---

## 2026-08-07: Async single-writer audit buffer for verify_success only (DEVIATES FROM PRD 8.5 timing)
**Decision**: `verify_success` audit events are appended to an in-process queue and
flushed in batches by one background writer task. Every other event type
(`token_minted`, `scope_escalation_denied`, `depth_limit_exceeded`, `revoke`,
`approval_*`, `rate_limit_exceeded`, `circuit_opened`, `anomaly_detected`) is written
synchronously before the response returns.
**Reason**: PRD item 8 targets p95 < 20ms on `/verify`, which sits in the hot path of
every agent action, while PRD 8.5 requires a hash chain whose `prev_hash` depends on the
immediately preceding row. That is a read-modify-write on a single tail row — a hard
serialization point. Buffering the high-volume, low-stakes event type keeps the chain
intact (a single writer means rows can never interleave, which is *stronger* than
concurrent synchronous writers) while keeping every security *decision* durable before
the caller is told the outcome.
**Rejected alternative**: (1) Fully synchronous writes — rejected, misses the latency
target and serializes the hot path. (2) Don't audit successful verifies — rejected,
destroys the "why did this agent get to do that" trail, which is a stated PRD goal.
**Constraint created**: Denials and mints MUST stay synchronous — a security decision the
caller acted on must be durable before the caller learns the outcome. Only
`verify_success` may be buffered. Tests that assert on buffered events must call
`AuditLogger.flush()` first. Known accepted risk: a hard crash can lose up to
`audit_buffer_max_size` verify-success rows (documented in the README threat model).

---

## 2026-08-07: Opaque UUID subjects in tokens; salted hashes in the audit log (RESOLVES PRD 5/8.6 CONTRADICTION)
**Decision**: Token claims (`sub`, `issued_for`, every `delegation_chain[].agent_id`)
carry opaque identifiers of the form `human:<uuid4>` / `agent:<uuid4>`. The
`subject_map` table stores `subject_id → (sha256(identifier+salt), display_label)` and is
keyed on the salted hash so the same logical agent always resolves to the same subject id.
`audit_log.actor_hash` stores the salted hash; `audit_log.actor_id` stores the opaque id.
Human-readable labels are resolved server-side, for the dashboard and `/audit/chain` only.
**Reason**: PRD 8.6 requires opaque identifiers "wherever the token crosses a trust
boundary" and salted hashing of user-linked data in the audit log. A capability token
crosses a trust boundary by definition — it is handed to a subordinate agent. But PRD
Section 5's example payload embeds `"human:jalp"` in `issued_for` and in every chain
entry. The privacy requirement is the stronger constraint, so it wins.
**Rejected alternative**: Readable ids in the token with hashing only in the audit log —
rejected because the token is precisely the artifact that leaves the trust boundary, so
hashing only the log protects the wrong surface.
**Constraint created**: Never put a raw `human_id` or caller-supplied agent name into a
JWT claim or an `audit_log.actor_id`. Go through
`SubjectRegistry.resolve_or_create()`. Because the map is keyed on the salted hash,
rotating `ADF_PII_SALT` orphans all existing subject mappings — treat it as a data
migration, not a config change.

---

## 2026-08-07: Guardrail-exempt agent allowlist for the latency benchmark
**Decision**: `ADF_GUARDRAIL_EXEMPT_AGENTS` lists agent ids that bypass rate limiting and
are excluded from circuit-breaker error accounting. The item-8 benchmark runs as
`bench-agent`.
**Reason**: PRD item 8 asks for p95 latency on `/verify` under load, but PRD 8.1 caps
verify at 300 calls/min/agent and PRD 8.3 opens the breaker at a 25% error rate. Run
naively, the benchmark would measure the rate limiter rejecting requests, not the
checkpoint doing work. Exempting one identity keeps every other code path real — signature
verification, revocation lookup, scope check and audit buffering all still execute.
**Rejected alternative**: (1) A global `GUARDRAILS_ENABLED=false` flag — rejected because
then the benchmark measures a code path that never runs in production. (2) Spreading load
across many synthetic agent ids — viable and more realistic, but it also measures
per-agent Redis key churn rather than steady-state verification cost; kept as an option
in the locustfile.
**Constraint created**: The exempt list MUST be empty in any production deployment. An
exempt agent id is effectively an unthrottled key. The README calls this out.

---

## 2026-08-07: Policy denials are distinguished from system faults for the circuit breaker (DEVIATES FROM PRD 8.3 default)
**Decision**: `CircuitBreaker.record()` takes a `policy_denial` flag. Blocked scope
escalations, depth-limit rejections, revoked/expired token refusals and malformed-token
rejections are marked as policy denials. Whether they count toward the error rate is
controlled by `ADF_CIRCUIT_COUNT_POLICY_DENIALS`, which **defaults to true** to match PRD
8.3 ("verify failures + delegate rejections"). The test suite sets it to false except in
`tests/test_circuit_breaker.py`, which exercises the PRD default explicitly.
**Reason**: Found by a failing test. PRD 8.3 counts every rejection toward the breaker,
which means a client that floods deliberately over-privileged delegations — or simply
posts garbage strings — drives the error rate to 100% and opens the circuit for **every
other agent**. The firewall doing its job correctly becomes a denial-of-service vector,
and an unauthenticated one at that, since a malformed token needs no credential. A
breaker should trip on evidence the *system* is unhealthy, not on evidence that clients
are behaving badly and being correctly refused.
**Rejected alternative**: (1) Follow PRD 8.3 unconditionally — rejected, it is a trivially
exploitable availability hole. (2) Drop policy denials from the breaker entirely —
rejected, because a genuine flood of denials can also indicate a real fault (a
misconfigured fleet, a mass revocation), and an operator may legitimately want to know.
Making it configurable keeps both readings available.
**Constraint created**: Any new denial path must pass `policy_denial=True` if it
represents the firewall working as designed. Only faults that indicate genuine system
distress should be recorded as plain errors. The escalation matrix in eval item 1 depends
on this: with the PRD default and no flag, hundreds of denials open the breaker and 403
responses become 503, so the test would measure the breaker rather than the subset rule.

---

## 2026-08-07: Redis cache-readiness sentinel (fixes a fail-open found by a test)
**Decision**: `rebuild_cache()` writes an `adf:cache_ready` key **last**, and
`is_revoked()` consults the Redis revocation set only when that key exists. A missing
sentinel means the cache was flushed or restarted, so the lookup falls through to
Postgres and opportunistically rebuilds.
**Reason**: `test_revocation_survives_total_cache_loss` failed on the first
implementation. Postgres was correctly the source of truth *for writes*, but the read path
still trusted Redis whenever Redis was merely *reachable*. After a flush the revocation
set is empty and `SISMEMBER` returns false for every jti, so revoked tokens verified as
valid — the exact fail-open the Postgres-truth design was supposed to eliminate. Reachable
and populated are different properties, and only the second one makes the cache
authoritative.
**Rejected alternative**: Query Postgres on every cache miss — correct but pointless:
a miss is the common case for a healthy token, so this would put a database round trip on
the hot path of every single verification and negate the reason for having a cache.
**Constraint created**: Never add a Redis read path that treats "key absent" as
"authoritative negative" without first confirming the sentinel. Any new cache warm-up code
must set the sentinel only after the data is fully written.

---

## 2026-08-07: Anomaly detection falls back to a relative margin on zero-variance baselines
**Decision**: When an agent's baseline has zero standard deviation, the sigma test is
replaced by a relative-margin comparison (`_is_high_outlier` / `_is_low_outlier`).
**Reason**: Found by a failing test. With `std == 0`, `value > mean + sigma * std`
degenerates to `value > mean`, which fires on any increase at all, and no multiple of zero
can ever express "well outside normal". The perverse result is that the *most predictable*
agents — the ones whose deviations carry the most signal — were the least detectable. An
agent that requested exactly one scope fifteen times and then asked for twenty-five
produced no finding.
**Rejected alternative**: Seed the baseline with synthetic variance — rejected, it
fabricates data and makes the threshold meaningless.
**Constraint created**: Anomaly findings remain log-only (PRD 8.7). Do not wire this into
a denial path; a false positive on a heuristic would become an outage on the hot path.

---

## 2026-08-07: `max_depth` is an optional per-root field with a config default (FILLS PRD 5/6.1 GAP)
**Decision**: `POST /tokens/root` accepts an optional `max_depth` (1–32). When omitted it
falls back to `ADF_MAX_DELEGATION_DEPTH` (default 5). The value is copied into every
descendant token and is immutable thereafter — a child always inherits its parent's
`max_depth` and cannot raise it.
**Reason**: PRD Section 5 describes `max_depth` as "hard ceiling, copied from root
config" but Section 6.1's root-mint request body has no such field, so the value had no
defined origin. Making it a per-root override with a config default satisfies both
readings and lets the eval harness test depth limits without restarting the service.
**Rejected alternative**: Global config only — rejected because testing several ceilings
would require a restart, and different root tokens legitimately warrant different depths.
**Constraint created**: `mint_child` MUST copy `parent.max_depth` verbatim. Never read
`max_depth` from a delegate request; a child that could widen its own ceiling would defeat
the depth guarantee.

---

## 2026-08-07: `root_jti` added to the token schema (ADDITION TO PRD 5)
**Decision**: Added a `root_jti` claim recording the jti of the root token the chain
terminates at.
**Reason**: PRD Section 5 rule 5 requires that "every chain must terminate at a valid,
non-expired, non-revoked root token". Without `root_jti`, checking that means walking
`delegation_chain[0]` and trusting a client-supplied array. `root_jti` lets the engine
verify the root's liveness directly against `token_record` / the revocation store, and it
gives the dashboard an O(1) grouping key for rendering delegation trees.
**Rejected alternative**: Derive the root from `delegation_chain[0].jti` — rejected as it
trusts client-supplied structure for a security check (the chain is signed, so it is not
forgeable, but an explicit indexed claim is clearer and cheaper to query).
**Constraint created**: `root_jti` is set once at root mint and copied unchanged by every
descendant. It must never be recomputed from the chain.

---

## 2026-08-07: Demo performs the human approval step explicitly (RESOLVES PRD 11/8.2 CONTRADICTION)
**Decision**: `send_email` stays in `sensitive_scopes.yaml`. The Section 11 demo script
shows the Email Agent's delegation returning `202 pending_approval`, then calls
`POST /tokens/approve` as the human, then collects the token — narrating each step.
**Reason**: PRD Section 11 step 2 says the `send_email` delegation "succeeds instantly",
but PRD 8.2 lists `send_email` as sensitive and therefore requiring human approval. Both
cannot hold. Removing `send_email` from the sensitive list would make the demo simpler but
would leave the approval gate — a headline guardrail — unexercised in the demo.
**Rejected alternative**: (1) Drop `send_email` from the sensitive list — rejected, hides
a feature. (2) An `AUTO_APPROVE` demo flag — rejected, a bypass switch for a security
control is a liability that would eventually be set in a real deployment.
**Constraint created**: The demo MUST NOT bypass the approval gate; it must satisfy it.
Do not add a config flag that skips approval.

---

## 2026-08-07: SQLite + fakeredis for tests, Postgres + Redis for production
**Decision**: The eval harness runs against in-memory SQLite and `fakeredis`; production
runs Postgres and Redis via docker-compose. Models therefore use only backend-neutral
column types (`JSON` not `JSONB`, `String` not `UUID`), and the SQLite engine is
configured with `StaticPool` + `check_same_thread=False`.
**Reason**: The harness must be runnable with a single `pytest -q` and no Docker daemon,
otherwise it stops being run. `StaticPool` is required because FastAPI's `TestClient`
executes endpoint code on a worker thread while the test body holds the same in-memory
database — with the default pool each thread gets its own empty database and every test
fails confusingly.
**Rejected alternative**: (1) testcontainers — highest fidelity but adds a Docker
dependency to the primary gate. (2) Postgres-only — rejected, makes the gate
environment-dependent.
**Constraint created**: Never use a Postgres-specific column type or SQL construct in
`models/`. `docker compose up` remains the integration-fidelity check; per HARNESS
Part 7, SQLite green is not evidence that the Postgres path works.

---

## 2026-08-07: Latency and revocation tests report measured numbers rather than asserting the PRD target
**Decision**: `tests/test_load_verify.py` and `tests/test_revocation.py` print p50/p95/p99
and revocation-propagation latency, and assert only against a generous ceiling well above
the PRD targets (p95 < 20ms, revocation < 50ms). `docs/results.md` records the real
measured values from an actual run.
**Reason**: A benchmark tuned until it passes its own target is not evidence. The honest
artifact is the measured number plus the environment it was measured in. A hard assert at
exactly 20ms would also be flaky on shared CI hardware, and a flaky gate gets disabled —
which loses the signal entirely.
**Rejected alternative**: Assert `p95 < 20` — rejected as flaky and as an incentive to
tune the test rather than the system.
**Constraint created**: Never hand-edit numbers in `docs/results.md`. Regenerate it with
`python -m tests.generate_results` and state the hardware.

---
## 2026-08-08: `agperms` extracted as an embeddable library; storage abstracted behind one protocol
**Decision**: The enforcement engines were re-implemented as a standalone,
pip-installable package (`agperms/`, published as `agperms`) that runs in-process with
**zero external services**. Storage sits behind a single `Storage` protocol with two
conforming backends: `MemoryStorage` (the dependency-free default) and `SqlStorage`
(durable, `agperms[sql]`). The FastAPI service in `checkpoint_service/` is untouched and
remains the hosted-mode deployment.
**Reason**: "How does someone use this in their project?" had no good answer. Both
existing installables assumed a running server: `agent-delegation-firewall` *is* the
server, and `langgraph-adf-adapter` is an HTTP client for it. Nobody reaches for a
permissions library expecting to stand up Postgres and Redis first. An embeddable core
makes `pip install agperms` followed by `Firewall()` actually work.
**Rejected alternative**: (1) Rename the HTTP adapter to `agperms` — rejected, it would
still require a service, which is the problem. (2) Make the existing service importable
as a library — rejected, `db/session.py` and `db/redis_client.py` hold process-wide
mutable globals (`_engine`, `_SessionLocal`, `_client`, `_available`), so two instances
in one process silently clobber each other's connections. A library cannot ship that.
**Constraint created**: `agperms` must never import from `checkpoint_service`, and must
keep working with `MemoryStorage` alone. Every engine takes its state by construction —
no module-level singletons — which `test_revocation.py::test_two_firewalls_are_independent`
pins down. New storage operations go in the protocol first, then both backends, then the
conformance suite that runs every test against both.

---

## 2026-08-08: One unit-atomic storage protocol, not two transaction lifecycles
**Decision**: Every `Storage` method is unit-atomic — the caller hands over a complete
operation and the backend makes it durable before returning. There is no
`begin()`/`commit()` in the protocol. Multi-row operations that must not tear
(`revoke_many`, `append_audit_batch`) get their own dedicated method so the backend can
make them atomic internally.
**Reason**: The service this was extracted from has two incompatible lifecycles: most
engines receive a `Session` per call and only `flush()`, while `AuditLogger` receives a
`sessionmaker` and owns its own transaction end-to-end (the sole `session.commit()` in
the engine layer). An in-memory backend cannot implement both coherently, and a protocol
that exposes explicit transactions would force every backend to fake one.
**Rejected alternative**: Expose a `UnitOfWork` context manager in the protocol —
rejected as the wrong shape for an in-memory dict, and it would leak SQLAlchemy's
transaction model into a contract that is supposed to be storage-agnostic.
**Constraint created**: The BFS ordering of `descendants_breadth_first` is part of the
contract, not an implementation detail — it is user-visible in `RevocationResult.revoked_jtis`
and asserted per-backend. `is_revoked` must raise `StorageError` rather than return
`False` when it cannot determine the answer: returning "probably fine" at exactly the
moment the store is broken is the failure this library exists to prevent.

---

## 2026-08-08: In-flight action checkpointing (`fw.action`) — the genuine gap
**Decision**: Added a context manager, `Firewall.action(token, scope=, name=)`, that
records an action opening and closing. A revoke then classifies every action on the
revoked subtree as `CLEAN`, `PARTIAL`, or `UNKNOWN` and queues anything not-CLEAN for
human review. The classifier (`classify_action`) is a pure function so the rule is
testable without a firewall, a store, or a clock.
**Reason**: Research into the 2026 landscape found this space is now crowded —
`adk-agentmesh` advertises "monotonic narrowing", `wafers` does append-only attenuation
layers, `warden` does fail-closed retrieval with a tamper-evident trail, `ScopeGate`
(arXiv 2606.28679) formally audits per-call authorization, `MiniScope` (arXiv 2512.11147)
is the academic prior art, and `legant` ships RFC 8693 attenuation in Go. Every one of
them, and ADF as originally built, answers only *"can this agent still act?"* after a
revoke. None answers *"what was it in the middle of doing?"*. The IETF draft
`draft-sato-soos-mad-02` names this exact gap and specifies `completion_state`
CLEAN/PARTIAL/UNKNOWN with human escalation — but it is a paper spec with no
implementation. This is a runnable, tested one.
**Rejected alternative**: (1) A manual `fw.checkpoint()` call at safe points — rejected,
too easy to forget, and a forgotten checkpoint silently degrades to UNKNOWN. A context
manager cannot be half-used. (2) Making checkpoints also power a live "what is this agent
doing now" dashboard feed — rejected as scope creep; it would need a queryable
currently-open table with a different growth profile, and the revocation-safety case does
not require it.
**Constraint created**: `UNKNOWN` must never be treated as `CLEAN` (the draft's INV-15,
implemented literally and pinned by `test_inv15_unknown_is_never_clean`). Action events
are written **synchronously** — the *absence* of a closing row is what a revoke reads as
"nothing was in flight", so it must be durable before the guarded code runs. `action()`
verifies the capability on entry, so a revoked token cannot open an action at all.

---

## 2026-08-08: Checkpoints are forensic, not preventive — stated, not implied
**Decision**: The docstring, the README, and the "What this does NOT do" section all say
plainly that revoking a capability cannot interrupt code already executing inside a
`with fw.action(...)` block.
**Reason**: Nothing in-process can halt another running block, and a security library
that lets a reader believe otherwise is worse than one with no feature at all — the
reader would stop building the thing that actually protects them. `legant`'s own
`REVOCATION.md` is comparably blunt ("no zero-latency offline revocation… the feed does
not authenticate or authorize — it only denies"), and that honesty is the standard worth
matching.
**Rejected alternative**: Describing `action()` as a "kill switch" or "interrupt" —
rejected as false.
**Constraint created**: Any future doc or pitch for this feature must keep the
distinction between *knowledge* and *prevention* explicit. It buys you an answer to
"what happened", not the ability to stop it.

---

## 2026-08-08: The Checkpoint Service is kept; the library does not replace it
**Decision**: Both `agperms` (embeddable) and `checkpoint_service/` (hosted) stay. The
library is the single-process form; the service is the shared-authority form.
**Reason**: The question "now that we have a library, is the service still needed?" was
answered with a measurement rather than an opinion. Two `Firewall` instances writing to one
shared `SqlStorage`, with interleaved writes, **break the audit hash chain at row 3**
(`intact=False`, `prev_hash does not match the previous row's row_hash`). This is not a
fixable defect: chain integrity requires one writer computing `prev_hash` from the current
tail, `agperms` enforces that with a `threading.Lock`, and a lock cannot serialise across
processes. So a single process needs no service, and two processes sharing one authority
need exactly what the service is -- the one writer everyone else calls.
Four further cases keep it necessary: non-Python agents cannot `import agperms` and need
HTTP; the approvals queue and delegation-tree UI are HTTP + React; HS256 means any verifier
can also mint, so centralising verification keeps the signing key off every service that
merely checks a token; and a library called from inside an untrusted agent process can be
bypassed by that process, whereas a network boundary cannot.
**Rejected alternative**: (1) Delete the service and ship only the library -- rejected, it
would silently corrupt the audit chain in any multi-replica deployment, which is the exact
guarantee the project exists to provide. (2) Make the library multi-process safe with an
advisory lock or `SELECT ... FOR UPDATE` on the chain tail -- viable, but it turns a
zero-dependency library into one that requires a specific database's locking semantics,
and it re-serialises every write through the database anyway, which is what the service
already does more explicitly.
**Constraint created**: `agperms` documents "one process only" prominently, with the
measured failure. Any future claim that the library supersedes the service must first show
a multi-process integrity test passing. The real duplication problem -- two implementations
of the same rules, kept in sync only by two test suites -- is tracked as PROGRESS.md Known
Issue 3, and the fix is to make the service import the library rather than reimplement it.

---

## 2026-08-08: Failure reasons truncated to 200 characters; review notes go in the chain
**Decision**: `action_failed` rows store `truncate_reason(f"{type(exc).__name__}: {exc}")`,
capped at 200 characters with whitespace collapsed. `resolve_review(...)` requires a
non-empty `note`, and that note is written as its own hash-chained `review_resolved`
audit row rather than only onto the mutable review record.
**Reason**: Two different problems. An unbounded exception message in an append-only log
is both a storage issue and a disclosure risk, and 200 characters keeps the type name and
the useful head of the message while bounding both. Separately, a human's finding is the
part an auditor or insurer would actually want, so it belongs in the tamper-evident
record; the `pending_review` row is a lookup cache of a *conclusion* and the chain is the
*evidence*, and keeping the note in only one place means they can be cross-checked
instead of trusted blindly.
**Rejected alternative**: (1) Store only the exception type and discard the message —
rejected, it throws away the detail that makes a PARTIAL finding actionable. (2) A `note`
column on `pending_review` — rejected, two copies of "what the human said" can disagree,
and the mutable one is the weaker record.
**Constraint created**: Truncation bounds the blast radius, it does not sanitise — the
README says so, because a developer whose exception text embeds a card number would still
leak it within the 200-char window. `resolve_review` records a conclusion and never
un-revokes anything.

---

<!-- AGENT REMINDER:
  - Entries here are decisions, not documentation of the obvious.
  - If you deviate from docs/PRD.md, you MUST add an entry explaining why.
  - If you disagree with an entry, add a new dated entry that supersedes it. Don't delete.
-->
