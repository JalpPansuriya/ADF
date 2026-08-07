# Product Requirements Document
## Project: Agent Delegation Firewall (ADF)
### Authorization & Capability-Narrowing System for Multi-Agent AI Pipelines

**Version:** 1.0
**Owner:** Jalp
**Status:** Ready for build
**Target audience for this doc:** A coding agent (e.g. Claude Code, Cursor, Devin) that will implement this end-to-end from spec.

---

## 1. Problem Statement

Modern agentic AI systems (Google ADK, LangGraph, CrewAI, AutoGen) let one agent delegate work to another agent. When Agent A hands a task to Agent B, most frameworks copy or inherit permissions rather than narrowing them — meaning Agent B often ends up able to do things Agent A never should have allowed. There is no standard mechanism that:

1. Forces each delegation step to be a **strict subset** of the parent's permissions.
2. Cryptographically proves the entire chain of custody back to a human.
3. Allows instant revocation of an entire downstream delegation subtree.
4. Produces an auditable log of "why did this agent get to do that."

This is a documented, real, currently-unsolved gap in the agent tooling ecosystem (confirmed via research: Google ADK's delegation is LLM-judgment-based with no built-in permission-narrowing; third parties like Cerbos sell bolt-on authorization specifically because frameworks don't solve this natively; academic papers as of 2024–2025 propose `delegation_chain` and `delegation_constraints` concepts but no reference implementation is standard).

**This project builds that missing piece as a standalone service**, framework-agnostic, that any agent system can call into before executing an action.

---

## 2. Goals & Non-Goals

### 2.1 Goals
- Build a **Checkpoint Service** that mints, verifies, narrows, and revokes capability tokens for AI agents.
- Enforce **strict subset delegation**: a child agent can never receive more scope than its parent had at the moment of delegation.
- Maintain a **tamper-evident audit trail** of every delegation and every enforcement decision.
- Support **instant revocation propagation**: revoking a root token invalidates its entire downstream subtree.
- Provide **guardrails** an actual production AI team would require: rate limiting, circuit breaking, human-approval gates for sensitive scopes, anomaly flags.
- Ship a **working demo** with 3+ toy agents showing both a legitimate delegation chain succeeding and an over-privileged delegation attempt being blocked.
- Produce metrics that prove the system works (see Section 10, Eval Harness).

### 2.2 Non-Goals (explicitly out of scope for v1)
- This is NOT a replacement for OAuth2/OIDC for human-to-service auth. It sits on top of / alongside that, purely for agent-to-agent delegation.
- Not building a full multi-tenant SaaS product — single-tenant, self-hosted service is fine for v1.
- Not integrating with every agent framework — one reference integration (a small custom agent harness) is enough to prove the concept. Optional stretch: LangGraph adapter.
- No UI for end-users beyond a read-only audit dashboard.
- No distributed/multi-region deployment — single instance is fine.

---

## 3. Users & Use Case

**Primary user:** An AI engineering team building a multi-agent system (e.g. a personal assistant that delegates to a calendar agent, an email agent, a web-search agent) that needs to guarantee no agent can silently gain more power than it should have.

**Core use case walkthrough:**
1. A human logs in and is issued a **root token** with full scope (e.g. `["read_calendar","write_calendar","read_email","send_email","web_search"]`).
2. The human's top-level "Assistant Agent" receives this root token.
3. The Assistant Agent decides to delegate the task "check my calendar and email me a summary" to a "Calendar Agent" and an "Email Agent." It requests the Checkpoint Service to mint two child tokens:
   - Calendar Agent → `["read_calendar"]`
   - Email Agent → `["send_email"]`
4. The Email Agent, mid-task, tries to delegate to a "Web Search Agent" and requests scope `["web_search"]`. The Checkpoint Service **rejects this** because `web_search` was never in the Email Agent's own token — it cannot grant what it doesn't have.
5. Every mint, verify, and rejection is written to an immutable audit log with full chain lineage.
6. If the human revokes the root token, both the Calendar Agent's and Email Agent's tokens are instantly invalid, even though they were never directly touched.

---

## 4. System Architecture

```
┌──────────────┐        ┌─────────────────────────────┐        ┌────────────┐
│  Human /     │──mint──▶       CHECKPOINT SERVICE      │◀──calls│  Demo      │
│  Root Issuer │        │  (FastAPI)                    │        │  Agents    │
└──────────────┘        │                                │        │ (harness)  │
                         │  ┌──────────┐  ┌────────────┐ │        └────────────┘
                         │  │ Token    │  │ Delegation │ │
                         │  │ Engine   │  │ Engine     │ │
                         │  │ (PyJWT)  │  │ (subset    │ │
                         │  │          │  │  checker)  │ │
                         │  └──────────┘  └────────────┘ │
                         │  ┌──────────┐  ┌────────────┐ │
                         │  │ Revocation│ │ Guardrails │ │
                         │  │ Store     │ │ (rate      │ │
                         │  │ (Redis)   │ │  limit,    │ │
                         │  │           │ │  circuit   │ │
                         │  │           │ │  breaker,  │ │
                         │  │           │ │  approval) │ │
                         │  └──────────┘  └────────────┘ │
                         │  ┌──────────────────────────┐ │
                         │  │ Audit Log (hash-chained,  │ │
                         │  │ append-only, Postgres)    │ │
                         │  └──────────────────────────┘ │
                         └─────────────────────────────┘
                                       │
                                       ▼
                         ┌─────────────────────────────┐
                         │ Dashboard (Streamlit/React)  │
                         │ - Live delegation tree view  │
                         │ - Audit log viewer            │
                         │ - Revocation controls         │
                         └─────────────────────────────┘
```

### 4.1 Components
| Component | Responsibility |
|---|---|
| Token Engine | Mint, sign, verify JWTs using PyJWT |
| Delegation Engine | Enforce strict-subset rule, depth limits, chain integrity |
| Revocation Store | Fast lookup (Redis) of revoked token IDs / subtrees |
| Guardrails Layer | Rate limiting, circuit breaker, human-approval gate, anomaly flag |
| Audit Log | Postgres, append-only, hash-chained rows for tamper evidence |
| Dashboard | Visualize delegation trees and audit trail |
| Demo Agent Harness | 3+ toy agents that exercise the whole system |

---

## 5. Token Schema (Data Model)

JWT payload (claims):

```json
{
  "jti": "uuid-v4",                     // unique token id
  "sub": "agent_id or human_id",        // subject
  "iss": "checkpoint-service",          // issuer (always the service)
  "issued_for": "human:jalp | agent:<parent_jti>", // who authorized this mint
  "scopes": ["read_calendar", "send_email"],
  "delegation_chain": [
    {"agent_id": "human:jalp", "jti": "root-jti", "scopes": ["...all root scopes..."], "ts": "ISO8601"},
    {"agent_id": "assistant-agent", "jti": "parent-jti", "scopes": ["read_calendar","send_email"], "ts": "ISO8601"}
  ],
  "depth": 2,                            // how many hops from root
  "max_depth": 5,                        // hard ceiling, copied from root config
  "iat": 1234567890,
  "exp": 1234571490,                     // must be <= parent's exp
  "approval_required": false,            // true if scopes include sensitive ones
  "approved_by": null                    // filled if human approval was granted
}
```

**Rules enforced by the Delegation Engine at mint time:**
1. `child.scopes` MUST be a subset of `parent.scopes` (⊆, not ⊂ — equal is allowed, exceeding is not).
2. `child.exp` MUST be ≤ `parent.exp`.
3. `child.depth` = `parent.depth + 1`; reject if `child.depth > max_depth`.
4. `child.delegation_chain` = `parent.delegation_chain + [parent's own entry]`.
5. Every chain must terminate at a valid, non-expired, non-revoked root token issued by a human.
6. If any scope in `child.scopes` is in the configured **sensitive scopes list** (e.g. `send_email`, `spend_money`, `delete_data`), set `approval_required = true` and block minting until a human approves via the approval endpoint.

---

## 6. API Specification

Base URL: `/api/v1`

### 6.1 `POST /tokens/root`
Human-only endpoint. Mints a root token.
**Request:**
```json
{ "human_id": "jalp", "scopes": ["read_calendar","write_calendar","read_email","send_email","web_search"], "ttl_seconds": 3600 }
```
**Response `201`:**
```json
{ "token": "<jwt>", "jti": "...", "expires_at": "..." }
```
**Auth:** Requires a separate human auth mechanism (simple API key or password login is fine for v1 — this is not the focus of the project).

---

### 6.2 `POST /tokens/delegate`
Called by an agent (using its own token as bearer auth) to mint a narrower child token for a sub-agent.

**Headers:** `Authorization: Bearer <parent_token>`

**Request:**
```json
{ "child_agent_id": "email-agent", "requested_scopes": ["send_email"], "ttl_seconds": 600 }
```

**Response `201` (success):**
```json
{ "token": "<jwt>", "jti": "...", "scopes": ["send_email"], "approval_required": false }
```

**Response `403` (scope escalation attempt):**
```json
{ "error": "scope_escalation_denied", "requested": ["web_search"], "allowed_max": ["send_email"], "denied_scopes": ["web_search"] }
```

**Response `202` (pending human approval):**
```json
{ "status": "pending_approval", "approval_id": "uuid", "message": "send_email requires human approval" }
```

---

### 6.3 `POST /tokens/verify`
Called by any tool/action endpoint before executing an agent's request. This is the actual enforcement checkpoint.

**Request:**
```json
{ "token": "<jwt>", "required_scope": "send_email" }
```

**Response `200`:**
```json
{ "valid": true, "agent_id": "email-agent", "remaining_scopes": ["send_email"] }
```

**Response `401`:**
```json
{ "valid": false, "reason": "expired | revoked | invalid_signature | scope_not_granted | circuit_open" }
```

---

### 6.4 `POST /tokens/revoke`
Revokes a token and its entire downstream subtree.

**Request:** `{ "jti": "..." }`
**Response:** `{ "revoked": true, "subtree_count": 4 }`

Implementation: walk the audit log's parent→child edges (or maintain a live adjacency map in Redis) and add every descendant `jti` to the revocation set in one atomic operation.

---

### 6.5 `POST /tokens/approve` / `POST /tokens/deny`
Human approval endpoint for pending sensitive-scope delegations.
**Request:** `{ "approval_id": "uuid", "decision": "approve" }`

---

### 6.6 `GET /audit/chain/{jti}`
Returns the full delegation lineage for a token, root to leaf.

### 6.7 `GET /audit/log?agent_id=&since=&action=`
Paginated raw audit log query for the dashboard.

### 6.8 `GET /health`
Circuit breaker + system status (see Section 8.3).

---

## 7. Enforcement Logic — Detailed Pseudocode

```python
def delegate(parent_token: str, requested_scopes: list[str], ttl: int) -> Token:
    parent = verify_and_decode(parent_token)          # signature + exp + revocation check
    if not parent.valid:
        raise Unauthorized(parent.reason)

    check_rate_limit(parent.sub)                        # guardrail
    check_circuit_breaker()                              # guardrail

    denied = [s for s in requested_scopes if s not in parent.scopes]
    if denied:
        log_audit("scope_escalation_denied", parent, denied)
        raise Forbidden(denied_scopes=denied)

    if parent.depth + 1 > parent.max_depth:
        log_audit("depth_limit_exceeded", parent)
        raise Forbidden("max delegation depth reached")

    child_exp = min(now() + ttl, parent.exp)

    sensitive = [s for s in requested_scopes if s in SENSITIVE_SCOPES]
    if sensitive:
        approval = create_pending_approval(parent, requested_scopes)
        log_audit("approval_pending", parent, sensitive)
        return PendingApproval(approval.id)

    child = mint_token(
        sub=child_agent_id,
        scopes=requested_scopes,
        exp=child_exp,
        depth=parent.depth + 1,
        delegation_chain=parent.delegation_chain + [entry_for(parent)],
        max_depth=parent.max_depth,
    )
    persist_edge(parent.jti, child.jti)                  # for revocation subtree walks
    log_audit("token_minted", child)
    return child
```

```python
def verify(token: str, required_scope: str) -> VerifyResult:
    if is_revoked(token.jti):                # O(1) Redis lookup, includes subtree revocations
        return invalid("revoked")
    if token.exp < now():
        return invalid("expired")
    if not signature_valid(token):
        return invalid("invalid_signature")
    if required_scope not in token.scopes:
        return invalid("scope_not_granted")
    if circuit_is_open():
        return invalid("circuit_open")
    log_audit("verify_success", token, required_scope)
    return valid(token)
```

---

## 8. Guardrails (Non-Negotiable for v1)

### 8.1 Rate Limiting
- Per-agent (`sub` claim) sliding-window rate limit on `/delegate` and `/verify` calls.
- Suggested default: 60 delegate calls/min, 300 verify calls/min per agent. Configurable.
- Implementation: Redis `INCR` + `EXPIRE` sliding window, or `redis-py` + `slowapi` middleware.

### 8.2 Human-Approval Gate
- Config file `sensitive_scopes.yaml` lists scopes requiring approval (e.g. `send_email`, `spend_money`, `delete_data`, `post_public_content`).
- Any delegation requesting a sensitive scope pauses in `pending` state until `POST /tokens/approve` is called by a human.
- Approval requests expire after a configurable timeout (default 5 min) if not acted on.

### 8.3 Circuit Breaker
- Track rolling error rate (verify failures + delegate rejections) over a 60-second window.
- If error rate exceeds threshold (default 25%) OR cost/call-volume spikes beyond configured ceiling, flip to `circuit_open` state.
- While open: all `/verify` calls return `401 circuit_open` and `/delegate` calls are blocked, except a designated human "break glass" endpoint to reset.
- Expose current state at `GET /health`.

### 8.4 Revocation & Subtree Kill
- Revoking any token immediately invalidates all descendants — this must be provably instant (test this explicitly, see Section 10).
- Store parent→child edges in Redis as a set (`edges:{parent_jti} -> {child_jti, ...}`) at mint time for O(depth) subtree walks.

### 8.5 Audit Log Integrity
- Every row in the `audit_log` Postgres table includes `prev_hash` = SHA-256 of the previous row's content, forming a hash chain.
- On each write, recompute and store `row_hash = sha256(prev_hash + row_content)`.
- Provide a `GET /audit/verify_integrity` endpoint that walks the whole chain and reports the first broken link, if any — this is your "tamper evidence" proof for the demo.

### 8.6 PII / Privacy Boundary
- Agent identifiers should be opaque UUIDs, not human-readable names tied to real accounts, wherever the token crosses a trust boundary.
- If storing any user-linked data in the audit log (e.g. `human_id`), hash it before persisting (`sha256(human_id + salt)`) — store the mapping separately, access-controlled.

### 8.7 Anomaly Flag (stretch, include if time allows)
- Flag any agent whose delegation frequency or scope-diversity spikes more than N standard deviations above its rolling baseline. Log as `anomaly_detected`, don't auto-block — just surface on the dashboard.

---

## 9. Tech Stack (exact choices — do not substitute without reason)

| Layer | Choice | Why |
|---|---|---|
| API framework | FastAPI (Python 3.11+) | async, native OpenAPI docs, FastAPI.security for bearer auth plumbing |
| Token library | PyJWT | industry standard JWT encode/decode/verify |
| Signing algorithm | HS256 for v1 (upgrade path to RS256 documented, not required) | simplicity first, note the upgrade path in README |
| Revocation store | Redis | O(1) lookups, TTL support, good fit for subtree adjacency |
| Audit log DB | PostgreSQL (via SQLAlchemy + Alembic for migrations) | durable, queryable, supports the hash-chain integrity pattern |
| Rate limiting | `slowapi` or custom Redis sliding window | simple FastAPI middleware integration |
| Dashboard | Streamlit (fastest) or a small React + Recharts app (stretch) | tree viz of delegation chains + audit log table |
| Demo agents | Plain Python classes calling OpenAI/Anthropic function-calling, or LangGraph if you want framework-realism | keep it minimal — the point is exercising the Checkpoint Service, not building elaborate agents |
| Containerization | Docker + docker-compose (api, redis, postgres, dashboard) | one-command spin-up for demo/interview purposes |
| Testing | pytest + httpx (async client) | for the eval harness in Section 10 |

---

## 10. Eval Harness — What "Done" Means

Build these as automated pytest cases, not just manual checks. This is what proves the project is "production-grade" rather than a tutorial:

1. **Scope escalation always fails** — parametrized test: for every combination of parent scopes and a superset request, `/delegate` must return `403`. Target: 100% block rate, 0 false negatives.
2. **Legitimate narrowing always succeeds** — for any subset request within TTL and depth limits, `/delegate` returns `201`.
3. **Revocation propagation latency** — mint a 3-level-deep chain, revoke the root, assert all descendants return `revoked` on `/verify` within X ms (measure and report this number — target under 50ms with Redis).
4. **Chain reconstruction accuracy** — for any leaf token, `GET /audit/chain/{jti}` must return a lineage that exactly matches the actual mint history.
5. **Circuit breaker trips correctly** — synthetically spike the error rate past threshold and assert `/verify` starts returning `circuit_open` within one evaluation window.
6. **Audit log tamper detection** — manually corrupt one row in the DB in a test, assert `/audit/verify_integrity` correctly identifies the broken hash link.
7. **Approval gate blocks until human action** — request a sensitive scope, assert it stays `pending`, assert it only becomes usable after `/tokens/approve` is called, assert it's rejected after `/tokens/deny`.
8. **Checkpoint latency** — benchmark `/verify` under load (e.g. `locust` or simple async load test); report p50/p95 latency. Target: p95 under 20ms excluding network, since this sits in the hot path of every agent action.

**Deliverable:** a `results.md` or dashboard panel showing pass/fail + measured numbers for all 8 — this is your proof-of-work artifact for a resume/portfolio, not just working code.

---

## 11. Demo Scenario Script (what you actually show)

1. Human mints root token with 5 scopes.
2. "Assistant Agent" delegates two narrower tokens to "Calendar Agent" (`read_calendar`) and "Email Agent" (`send_email`) — show both succeed instantly, show the dashboard tree update live.
3. "Email Agent" attempts to delegate `web_search` to a new "Web Search Agent" — show the `403 scope_escalation_denied` response and the audit log entry.
4. "Email Agent" attempts to actually call `send_email` (a mock action) with its valid token — show `/verify` succeed, action executes.
5. Human revokes the root token — show, live, that both Calendar Agent's and Email Agent's tokens instantly fail `/verify`, and the dashboard tree greys out the whole subtree.
6. Pull up `/audit/chain/{jti}` for the Email Agent's token — show the full human-to-agent lineage.
7. Run `/audit/verify_integrity` — show it passes; then (in a separate test run) show it correctly catches a tampered row.

---

## 12. Folder Structure

```
agent-delegation-firewall/
├── docker-compose.yml
├── README.md
├── checkpoint_service/
│   ├── main.py                  # FastAPI app entrypoint
│   ├── config.py                # sensitive_scopes, rate limits, thresholds
│   ├── models/
│   │   ├── token.py             # Pydantic schemas for JWT payload
│   │   └── audit.py             # SQLAlchemy models for audit_log table
│   ├── engine/
│   │   ├── token_engine.py      # mint/verify via PyJWT
│   │   ├── delegation_engine.py # subset check, depth check, chain build
│   │   ├── revocation.py        # Redis subtree revocation logic
│   │   └── guardrails.py        # rate limit, circuit breaker, approval gate
│   ├── routes/
│   │   ├── tokens.py            # /tokens/* endpoints
│   │   └── audit.py             # /audit/* endpoints
│   └── db/
│       ├── session.py
│       └── migrations/          # Alembic
├── dashboard/
│   └── app.py                   # Streamlit dashboard
├── demo_agents/
│   ├── assistant_agent.py
│   ├── calendar_agent.py
│   ├── email_agent.py
│   └── run_demo.py              # scripted end-to-end scenario from Section 11
├── tests/
│   ├── test_delegation_rules.py
│   ├── test_revocation.py
│   ├── test_circuit_breaker.py
│   ├── test_audit_integrity.py
│   └── test_load_verify.py
└── docs/
    ├── PRD.md                   # this document
    └── results.md                # eval harness output
```

---

## 13. Milestones & Timeline

| Week | Deliverable |
|---|---|
| 1 | Token schema finalized; `/tokens/root`, `/tokens/delegate`, `/tokens/verify` working with in-memory revocation; subset-check enforced; basic pytest suite for Section 10 item 1–2 |
| 2 | Redis-backed revocation with subtree walk; Postgres audit log with hash chaining; `/audit/chain` and `/audit/verify_integrity` endpoints; tests for item 3, 4, 6 |
| 3 | Rate limiting, circuit breaker, human-approval gate; tests for item 5, 7; load test for item 8 |
| 4 | Demo agents built; scripted demo (Section 11) working end-to-end; Streamlit dashboard with live tree + audit table; docker-compose one-command spin-up; README written as a mini security whitepaper with architecture diagram, threat model, and results.md numbers |

---

## 14. README / Documentation Requirements

The final README must include:
1. One-paragraph problem statement (why this gap exists, citing that major frameworks don't solve it natively).
2. Architecture diagram (Section 4).
3. Quickstart: `docker-compose up`, then run `demo_agents/run_demo.py`.
4. API reference (can be auto-generated from FastAPI's OpenAPI docs, linked).
5. Threat model: what this does and does not protect against (e.g. it does not protect against a compromised Checkpoint Service itself, a malicious human root-issuer, or prompt-injection causing an agent to *request* a legitimate-looking but harmful action within its granted scope — note these explicitly as out-of-scope limitations, this shows engineering maturity).
6. Results table from the eval harness (Section 10) with real measured numbers.
7. Upgrade path notes: HS256 → RS256, single-instance Redis → Redis Cluster, single Postgres → replicated, for "how would this scale" conversations.

---

## 15. Decisions (Locked)

These were open questions in draft v1 — now finalized. The rest of this document should be read with these choices applied.

- **Human root-mint auth:** Simple static API key. `POST /tokens/root` requires header `X-Admin-Key: <key>`, checked against an env var (`ADMIN_API_KEY`). No login flow, no user table for v1. Reject with `401` if missing/wrong. Rotate by changing the env var and restarting the service — document this in the README as the known v1 limitation (single shared key, no per-human identity yet).
- **LangGraph adapter:** Build it. See Section 16.
- **Dashboard:** React (not Streamlit). See Section 17 for the updated stack entry and structure.

---

## 16. LangGraph Adapter (New — Required Component)

**Purpose:** Prove the Checkpoint Service is framework-agnostic by wrapping it as a reusable LangGraph component, not just a custom demo harness. This is what you point to when someone asks "does this actually work with real agent frameworks or just your toy example."

### 16.1 What it is
A small Python package (`langgraph_adf_adapter/`) that plugs the Checkpoint Service into a LangGraph graph at two points:
1. **Node-entry guard** — before a LangGraph node runs, it must present a valid ADF token with the scope that node requires.
2. **Delegation hook** — when a LangGraph graph spawns a sub-graph or hands off state to another agent node, the adapter calls `/tokens/delegate` automatically instead of just passing state through unchecked.

### 16.2 Interface design

```python
# langgraph_adf_adapter/guard.py

from functools import wraps
from adf_client import ADFClient  # thin wrapper around httpx calling the Checkpoint Service

class ADFGuard:
    def __init__(self, checkpoint_url: str, admin_key: str | None = None):
        self.client = ADFClient(checkpoint_url, admin_key)

    def require_scope(self, scope: str):
        """Decorator for a LangGraph node function. Reads `token` out of
        the graph state, verifies it against `scope` before the node body runs."""
        def decorator(node_fn):
            @wraps(node_fn)
            def wrapped(state: dict, *args, **kwargs):
                token = state.get("adf_token")
                result = self.client.verify(token, scope)
                if not result.valid:
                    raise PermissionError(f"ADF denied: {result.reason}")
                return node_fn(state, *args, **kwargs)
            return wrapped
        return decorator

    def delegate_for_node(self, parent_state: dict, child_agent_id: str,
                           requested_scopes: list[str], ttl_seconds: int = 600) -> dict:
        """Call before dispatching to a sub-agent node. Returns updated
        state dict with the new narrowed token injected, or raises on
        scope escalation."""
        parent_token = parent_state["adf_token"]
        child_token = self.client.delegate(parent_token, child_agent_id,
                                            requested_scopes, ttl_seconds)
        return {**parent_state, "adf_token": child_token.token, "adf_agent_id": child_agent_id}
```

### 16.3 Usage inside a LangGraph graph

```python
from langgraph.graph import StateGraph
from langgraph_adf_adapter.guard import ADFGuard

adf = ADFGuard(checkpoint_url="http://localhost:8000", admin_key=None)

@adf.require_scope("send_email")
def email_node(state):
    # actual email-sending logic here — only runs if token has send_email
    ...

def assistant_node(state):
    # decides to delegate to email_node's agent identity
    new_state = adf.delegate_for_node(
        state, child_agent_id="email-agent",
        requested_scopes=["send_email"], ttl_seconds=600,
    )
    return new_state

graph = StateGraph(dict)
graph.add_node("assistant", assistant_node)
graph.add_node("email", email_node)
graph.add_edge("assistant", "email")
```

If `assistant_node` tries to request a scope it doesn't itself hold (e.g. `web_search` when its own token only has `send_email` + `read_calendar`), `delegate_for_node` raises before the sub-graph ever runs — the same 403 enforcement as the raw API, just wrapped in LangGraph idioms.

### 16.4 Adapter test requirements
Add to the eval harness (Section 10):
9. **LangGraph integration test** — build a 3-node LangGraph graph (assistant → calendar, assistant → email) using the adapter; assert legitimate delegation flows execute end-to-end, and assert an over-privileged node dispatch raises `PermissionError` before the node body executes (i.e. side effects never happen).

### 16.5 Folder addition
```
├── langgraph_adf_adapter/
│   ├── __init__.py
│   ├── adf_client.py        # thin httpx wrapper for the Checkpoint Service API
│   └── guard.py              # ADFGuard: require_scope decorator + delegate_for_node
```

### 16.6 Package it properly
Ship this as an installable local package (`pyproject.toml` with `pip install -e ./langgraph_adf_adapter`) rather than a loose script — this is the difference between "I called an API in a demo" and "I built a reusable integration," which is the stronger portfolio claim.

---

## 17. Dashboard — React (Replaces Streamlit)

### 17.1 Stack
| Piece | Choice |
|---|---|
| Framework | React + Vite |
| Data fetching | TanStack Query (React Query) against the Checkpoint Service REST API |
| Tree visualization | `react-d3-tree` or a hand-rolled SVG tree (recommend `react-d3-tree` — purpose-built for hierarchical delegation trees) |
| Styling | Tailwind CSS |
| Charts (rate limit / circuit breaker status over time) | Recharts |
| Live updates | Polling every 2s on `/audit/log` and `/health` is sufficient for v1; WebSocket push is a stretch goal, not required |

### 17.2 Screens
1. **Delegation Tree** — live tree view rooted at each active root token, showing agent nodes, scopes per node, and greying out/marking revoked subtrees in real time (poll-driven).
2. **Audit Log Table** — filterable/sortable table of every `mint / verify / delegate_denied / revoke / approval_pending` event, with a detail drawer showing the full JWT claims for that row.
3. **Approvals Queue** — pending human-approval requests for sensitive scopes, with Approve/Deny buttons wired to `/tokens/approve` and `/tokens/deny`.
4. **System Health** — circuit breaker state, current error rate, rate-limit stats per agent, and a button to hit `GET /audit/verify_integrity` on demand with a pass/fail banner.

### 17.3 Folder addition (replaces the old `dashboard/app.py` entry in Section 12)
```
├── dashboard/
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/client.ts          # typed fetch wrapper for Checkpoint Service
│   │   ├── components/
│   │   │   ├── DelegationTree.tsx
│   │   │   ├── AuditLogTable.tsx
│   │   │   ├── ApprovalsQueue.tsx
│   │   │   └── SystemHealth.tsx
│   │   └── pages/
│   │       └── Dashboard.tsx
│   └── tailwind.config.js
```

### 17.4 docker-compose addition
Add a `dashboard` service building the Vite app (or run `npm run dev` locally against the containerized API during development; containerize with a multi-stage Dockerfile + nginx for the demo-ready build).

---

## 18. Updated Milestones (Supersedes Section 13)

| Week | Deliverable |
|---|---|
| 1 | Token schema; `/tokens/root` (static API key auth), `/tokens/delegate`, `/tokens/verify` with in-memory revocation; subset-check enforced; pytest items 1–2 |
| 2 | Redis-backed revocation with subtree walk; Postgres hash-chained audit log; `/audit/chain`, `/audit/verify_integrity`; pytest items 3, 4, 6 |
| 3 | Rate limiting, circuit breaker, human-approval gate; pytest items 5, 7, 8; **LangGraph adapter built + integration test (item 9)** |
| 4 | Demo agents (native + LangGraph versions) fully working; **React dashboard** with all 4 screens wired to live API via polling; docker-compose one-command spin-up; README as security whitepaper with results.md numbers |

---

**End of PRD.** Hand this document directly to your coding agent along with the folder structure in Sections 12, 16.5, and 17.3 as the starting scaffold instruction.
