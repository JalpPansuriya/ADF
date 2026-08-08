# agperms

**Capability narrowing and in-flight revocation forensics for multi-agent AI systems.**

```bash
pip install agperms
```

Two things this does that a permission check does not:

**Narrowing is enforced, not requested.** A delegated capability can only ever be
a subset of the one it came from. The check runs against the freshly verified
parent token, so neither a stale record nor the caller's own claim can widen a
grant. This holds transitively: an agent that lost a scope one hop ago cannot
re-grant it, even if the original human root token had it.

**Revocation tells you what was mid-flight.** Every other tool answers *"can this
agent still act?"* after a revoke. Wrap side-effecting work in `fw.action(...)` and
a revoke also answers *"what was it in the middle of doing?"* — reporting each open
action as `CLEAN`, `PARTIAL`, or `UNKNOWN` instead of leaving you to guess.

---

## Quick start

```python
from agperms import Firewall

fw = Firewall()   # no server, no database, no config

# A human grants a capability.
root = fw.mint_root(subject="alice", scopes=["read_calendar", "read_email"])

# An agent narrows it for a sub-agent. Never widens.
child = fw.delegate(root.token, to="calendar-agent", scopes=["read_calendar"])

# Check before acting.
if fw.verify(child.token, "read_calendar"):
    ...
```

Escalation is refused, not logged-and-allowed:

```python
from agperms import ScopeEscalationDenied

try:
    fw.delegate(child.token, to="sneaky", scopes=["read_email"])
except ScopeEscalationDenied as exc:
    print(exc.denied_scopes)   # ['read_email']
```

Note what happened there: the human's root token *did* hold `read_email`, but
`child` never carried it forward, so `child` has nothing to grant. Narrowing is
transitive.

## In-flight actions

Wrap anything with a side effect:

```python
with fw.action(child.token, scope="send_email", name="welcome_email"):
    send_email(draft)          # the irreversible bit
```

Now a revoke can classify it:

```python
result = fw.revoke(root.jti, reason="incident-42")

for review in result.reviews:
    print(review.action_name, review.classification)
    # welcome_email CompletionState.PARTIAL
```

| Classification | Means |
|---|---|
| `CLEAN` | The block completed normally. Nothing to review. |
| `PARTIAL` | It started and raised. Something may have happened. |
| `UNKNOWN` | It started and no closing record exists — the process died mid-block. |

`UNKNOWN` is **never** silently treated as `CLEAN`. An action with no closing
record might have finished, or might have taken an irreversible step and died, and
those are different facts. The library refuses to resolve that ambiguity in the
convenient direction.

Close the loop with a human's finding, which is written into the audit chain
rather than a mutable column:

```python
for review in fw.pending_reviews():
    fw.resolve_review(
        review.review_id,
        note="checked provider dashboard, no email was sent",
        reviewed_by="human:alice",
    )
```

## Human approval for sensitive scopes

Some scopes should never be delegated without a person looking. Those raise
instead of minting, and **no token exists** until approval:

```python
from agperms import ApprovalRequired

try:
    fw.delegate(root.token, to="email-agent", scopes=["send_email"])
except ApprovalRequired as pending:
    # Nothing was minted. Not a flagged token — no token at all.
    cap = fw.approve(pending.approval_id, approver="human:alice")
```

Default sensitive scopes: `send_email`, `spend_money`, `delete_data`,
`post_public_content`, `transfer_funds`, `execute_code`. Override with
`Config(sensitive_scopes=frozenset({...}))`.

## LangGraph

```python
from agperms import Firewall
from agperms.integrations.langgraph import AgpermsGuard, TOKEN_KEY

fw = Firewall()
guard = AgpermsGuard(fw)

@guard.require_scope("send_email")     # checkpointed automatically
def email_node(state):
    send_email(state["draft"])
    return {**state, "sent": True}

def assistant_node(state):
    return email_node(
        guard.delegate_for_node(state, to="email-agent", scopes=["send_email"])
    )
```

The guard raises **before** the node body runs, so a denial means the side effect
never happened — not that it happened and an error was reported. The node body is
wrapped in an action checkpoint named after the function, so a revoke mid-node
surfaces it. Exceptions are re-raised unchanged; the checkpoint is a side
observation, never a behaviour change. Pass `checkpoint=False` for pure nodes.

## Durability

The default is in-memory, which means **revocations die with the process**. That is
correct for tests and single-process embedding, and wrong for anything else:

```python
from agperms import Config, Firewall
from agperms.storage.sql import SqlStorage        # pip install 'agperms[sql]'

fw = Firewall(
    config=Config(jwt_secret=os.environ["AGPERMS_SECRET"]),  # fixed, not generated
    storage=SqlStorage("postgresql+psycopg://user:pass@host/db"),
)
```

Two things change here and both matter. A fixed `jwt_secret` means tokens survive
a restart and can be verified by another process — leaving it unset generates an
ephemeral key per instance. A durable `Storage` means a revoked capability stays
revoked.

Both backends are tested against the same conformance suite, so the SQL path
cannot quietly drift from the in-memory one.

### One process only

`agperms` is a single-process library. The audit chain's integrity depends on one
writer computing each row's hash from the current tail, which is enforced with an
in-process lock — and a lock cannot serialise across processes.

Two `Firewall` instances writing to one shared database **will fork the chain**:

```python
a = Firewall(config=cfg, storage=shared_store)
b = Firewall(config=cfg, storage=shared_store)
# ... interleaved writes from both ...
a.verify_audit_integrity()      # intact=False, break at row 3
```

That is a real limitation, not a bug to work around. If several processes or
machines must share one authority, put one process in front of the store and have
the others call it — that is what the
[Checkpoint Service](../README.md) in this repository is for. Use the library when
enforcement lives inside a single process; use the service when it has to be
shared.

## Guardrails

| Control | Default | Notes |
|---|---|---|
| Rate limit | 60 delegate/min, 300 verify/min per agent | Sliding window; pass a `RedisWindowCache` to share across processes |
| Circuit breaker | opens at 25% errors over 60s, min 20 samples | **No automatic recovery** — `fw.reset_circuit()` only |
| Approval gate | 300s timeout | No token exists while pending |
| Anomaly flag | 3σ over a 10-sample baseline | Log-only, never blocks |

Policy denials — a blocked escalation, a forged token — do **not** count toward the
breaker by default. Counting them lets any client open the breaker for everyone
else just by spamming requests that get correctly refused. Set
`circuit_count_policy_denials=True` if you want the stricter reading.

## Audit trail

Every decision is hash-chained: `row_hash = sha256(prev_hash + canonical_row)`.
Editing, deleting or reordering any row breaks the chain from that point on, and
the break is localisable:

```python
report = fw.verify_audit_integrity()
print(report.intact, report.rows_checked, report.first_broken_row_id)
```

Identifiers are pseudonymised before anything is stored. Tokens carry opaque
`human:<uuid>` / `agent:<uuid>` subjects, and the durable record keeps only
`sha256(identifier + salt)`. Rotating `pii_salt` orphans every existing mapping —
treat it as a data migration, not a config tweak.

## What this does NOT do

Stated plainly, because a security library that oversells itself is worse than one
that admits its edges.

- **It cannot interrupt code that is already running.** Revoking a capability does
  not halt a Python block that is mid-execution — nothing in-process can. What you
  get is *knowledge* (the next check fails, and the audit trail says what was open),
  not *prevention*. Checkpoints are a forensic tool, not a kill switch.
- **It is single-process.** Two instances sharing one store fork the audit chain
  (see [One process only](#one-process-only)). Use the Checkpoint Service when
  several processes need one shared authority.
- **A library can be bypassed by the process that calls it.** If the agent's own
  code is untrusted, enforcement belongs behind a network boundary, not inside the
  same interpreter.
- **Checkpoints are opt-in and manual.** If you forget to wrap a side effect, a
  revoke during that window has nothing to classify. The LangGraph guard closes
  this at node boundaries automatically; the raw SDK relies on you.
- **`UNKNOWN` is a real outcome, not a bug.** A crash mid-action genuinely leaves
  the fate unresolved. The library reports that honestly rather than guessing.
- **Exception messages are truncated to 200 characters and land in an immutable
  log.** Truncation bounds the blast radius; it does not sanitise. Don't put secrets
  in exception text.
- **In-memory storage is not durable.** A restart resurrects revoked capabilities.
  Use `SqlStorage` where that matters.
- **HMAC signing means every verifier needs the secret.** Fine in-process; for a
  distributed deployment, put verification behind one service rather than
  distributing the key.
- **It does not stop prompt injection.** If an agent legitimately holds
  `send_email` and is manipulated into sending a bad email, every check passes.
  This constrains *what* an agent can do, never *whether the intent was sound*.
- **The audit chain is tamper-evident, not tamper-proof.** Someone with
  unrestricted write access to the store can recompute the chain from a chosen
  point forward. Ship the chain tip somewhere append-only to close that.

## API

| Method | Purpose |
|---|---|
| `mint_root(subject=, scopes=, ttl_seconds=, max_depth=)` | Grant a depth-0 capability |
| `delegate(token, to=, scopes=, ttl_seconds=)` | Narrow it for a sub-agent |
| `verify(token, scope) -> VerifyResult` | Check; returns a falsy result rather than raising |
| `require(token, scope) -> TokenClaims` | Check; raises `Denied` |
| `action(token, scope=, name=)` | Context manager for a side-effecting action |
| `revoke(jti, reason=) -> RevocationResult` | Kill a capability and its whole subtree |
| `approve(approval_id, approver=)` / `deny(...)` / `collect(...)` | Approval gate |
| `pending_reviews()` / `resolve_review(id, note=, reviewed_by=)` | In-flight findings |
| `chain(jti) -> list[ChainHop]` | Rebuild lineage from durable records |
| `verify_audit_integrity() -> IntegrityReport` | Walk the hash chain |
| `circuit_state()` / `reset_circuit()` | Breaker status and break-glass |

## License

Apache-2.0
