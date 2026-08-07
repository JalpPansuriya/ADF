"""Generate ``docs/results.md`` from a real test run.

    python -m tests.generate_results

Never hand-edit the output. Every number below comes from executing the eval
harness on this machine; the environment is recorded alongside so the figures can
be interpreted rather than quoted out of context.
"""

from __future__ import annotations

import json
import pathlib
import platform
import re
import statistics
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_PATH = REPO_ROOT / "docs" / "results.md"

# (eval item, description, test target)
EVAL_ITEMS: list[tuple[str, str, str]] = [
    ("1", "Scope escalation always fails", "tests/test_delegation_rules.py::TestScopeEscalationAlwaysFails"),
    ("2", "Legitimate narrowing always succeeds", "tests/test_delegation_rules.py::TestLegitimateNarrowingAlwaysSucceeds"),
    ("3", "Revocation propagation (incl. cache-loss safety)", "tests/test_revocation.py"),
    ("4", "Chain reconstruction accuracy", "tests/test_audit_chain.py"),
    ("5", "Circuit breaker trips correctly", "tests/test_circuit_breaker.py"),
    ("6", "Audit log tamper detection", "tests/test_audit_integrity.py"),
    ("7", "Approval gate blocks until human action", "tests/test_approval_gate.py"),
    ("8", "Checkpoint latency benchmark", "tests/test_load_verify.py"),
    ("9", "LangGraph adapter integration", "tests/test_langgraph_adapter.py"),
]

SUPPORTING: list[tuple[str, str]] = [
    ("Config / secret hardening", "tests/test_config.py"),
    ("Token engine (signature, expiry, claim schema)", "tests/test_token_engine.py"),
    ("API contract (PRD Section 6 shapes)", "tests/test_api_contract.py"),
    ("Rate limiting + anomaly flagging", "tests/test_rate_limit.py"),
    ("Architectural boundary checks", "tests/test_boundaries.py"),
    ("End-to-end demo scenario (PRD Section 11)", "tests/test_demo_scenario.py"),
]


def _python() -> str:
    return sys.executable


def run_target(target: str) -> tuple[int, int, float, str]:
    """Run one pytest target. Returns (passed, failed, seconds, raw_output)."""
    started = time.perf_counter()
    proc = subprocess.run(
        [_python(), "-m", "pytest", target, "-q", "--no-header", "-s", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    elapsed = time.perf_counter() - started
    output = proc.stdout + proc.stderr
    passed = failed = 0
    match = re.search(r"(\d+) passed", output)
    if match:
        passed = int(match.group(1))
    match = re.search(r"(\d+) failed", output)
    if match:
        failed = int(match.group(1))
    return passed, failed, elapsed, output


def extract_measurements(output: str) -> list[str]:
    """Pull the ``[item N]`` measurement lines the tests print."""
    lines: list[str] = []
    capture = False
    for raw in output.splitlines():
        line = raw.rstrip()
        if re.match(r"^\[item \d+\]", line.strip()):
            capture = True
            lines.append(line.strip())
        elif capture:
            if line.startswith(("  ", "\t")) and line.strip():
                lines.append(line.strip())
            else:
                capture = False
    return lines


def measure_revocation_latency() -> dict[str, float]:
    """Measure revocation propagation directly, independent of pytest output."""
    import fakeredis
    from fastapi.testclient import TestClient

    sys.path.insert(0, str(REPO_ROOT))
    from checkpoint_service.container import AppContainer
    from checkpoint_service.db.session import dispose_engine
    from checkpoint_service.main import create_app
    from tests.conftest import ADFTestHelper, build_settings

    settings = build_settings(rate_limit_delegate_per_min=100_000)
    container = AppContainer(
        settings,
        redis_override=fakeredis.FakeRedis(decode_responses=True),
        create_tables=True,
    )
    samples: list[float] = []
    e2e: list[float] = []
    try:
        with TestClient(create_app(container)) as client:
            client.container = container  # type: ignore[attr-defined]
            adf = ADFTestHelper(client)
            for _ in range(20):
                chain = adf.build_chain(3, ["read_calendar"])
                response = adf.revoke(chain[0]["jti"])
                samples.append(response.json()["latency_ms"])
                # Time from revoke returning to a leaf actually being refused.
                t0 = time.perf_counter()
                result = adf.verify(chain[-1]["token"], "read_calendar")
                e2e.append((time.perf_counter() - t0) * 1000.0)
                assert result.json()["reason"] == "revoked"
    finally:
        dispose_engine()

    ordered = sorted(samples)
    return {
        "revoke_p50": statistics.median(ordered),
        "revoke_p95": ordered[int(0.95 * (len(ordered) - 1))],
        "revoke_max": max(ordered),
        "first_denial_p50": statistics.median(sorted(e2e)),
        "samples": len(samples),
    }


def environment() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "processor": platform.processor() or "unknown",
        "database": "SQLite in-memory (Postgres in production)",
        "cache": "fakeredis (Redis in production)",
    }


def build_report() -> str:
    env = environment()
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S %Z")

    rows: list[tuple[str, str, str, str, str]] = []
    measurements: dict[str, list[str]] = {}
    total_passed = total_failed = 0

    print("Running eval items...")
    for item, description, target in EVAL_ITEMS:
        print(f"  item {item}: {target}")
        passed, failed, elapsed, output = run_target(target)
        total_passed += passed
        total_failed += failed
        status = "PASS" if failed == 0 and passed > 0 else "FAIL"
        rows.append((item, description, status, f"{passed}/{passed + failed}", f"{elapsed:.1f}s"))
        found = extract_measurements(output)
        if found:
            measurements[item] = found

    support_rows: list[tuple[str, str, str, str]] = []
    print("Running supporting suites...")
    for description, target in SUPPORTING:
        print(f"  {target}")
        passed, failed, elapsed, _ = run_target(target)
        total_passed += passed
        total_failed += failed
        status = "PASS" if failed == 0 and passed > 0 else "FAIL"
        support_rows.append((description, status, f"{passed}/{passed + failed}", f"{elapsed:.1f}s"))

    print("Measuring revocation propagation...")
    revocation = measure_revocation_latency()

    lines: list[str] = []
    add = lines.append

    add("# Eval Harness Results")
    add("")
    add("<!-- GENERATED FILE. Do not edit by hand.")
    add("     Regenerate with: python -m tests.generate_results -->")
    add("")
    add(f"**Generated:** {generated_at}")
    add(f"**Python:** {env['python']}  ")
    add(f"**Platform:** {env['platform']}  ")
    add(f"**Datastores:** {env['database']}; {env['cache']}")
    add("")
    add(
        "Every number here comes from executing the suite on the machine described "
        "above. Nothing is hand-written."
    )
    add("")
    add("## Honest caveats")
    add("")
    add(
        "- Latency figures come from an **in-process** harness on SQLite + fakeredis. "
        "They are a lower bound for a containerised Postgres/Redis deployment across a "
        "network. Use `tests/locustfile.py` against `docker compose up` for a realistic "
        "figure."
    )
    add(
        "- Latency assertions use a deliberately generous ceiling. The tests *report* "
        "the measured value rather than being tuned until they pass the PRD target; a "
        "benchmark trimmed to hit its own goal is not evidence."
    )
    add(
        "- A green run here does not prove the Postgres path. Any change to `models/`, "
        "`revocation.py` or `db/session.py` needs the Layer-3 `docker compose` check."
    )
    add("")
    add("## Eval items (PRD Section 10 + 16.4)")
    add("")
    add("| # | Criterion | Status | Tests | Time |")
    add("|---|-----------|--------|-------|------|")
    for item, description, status, tests, elapsed in rows:
        add(f"| {item} | {description} | **{status}** | {tests} | {elapsed} |")
    add("")
    add("## Supporting suites")
    add("")
    add("| Area | Status | Tests | Time |")
    add("|------|--------|-------|------|")
    for description, status, tests, elapsed in support_rows:
        add(f"| {description} | **{status}** | {tests} | {elapsed} |")
    add("")
    add(f"**Total: {total_passed} passed, {total_failed} failed.**")
    add("")

    add("## Measured numbers")
    add("")
    add("### Item 1 -- scope escalation block rate")
    add("")
    if "1" in measurements:
        add("```")
        for line in measurements["1"]:
            add(line)
        add("```")
    add(
        "The escalation matrix is parametrized over every (parent, requested) pair "
        "drawn from the 5 demo scopes where the request is not a subset. Target: 100% "
        "block rate, 0 false negatives."
    )
    add("")

    add("### Item 3 -- revocation propagation")
    add("")
    add("| Metric | Value | PRD target |")
    add("|--------|-------|-----------|")
    add(f"| Subtree revoke, p50 | {revocation['revoke_p50']:.2f} ms | < 50 ms |")
    add(f"| Subtree revoke, p95 | {revocation['revoke_p95']:.2f} ms | < 50 ms |")
    add(f"| Subtree revoke, max | {revocation['revoke_max']:.2f} ms | < 50 ms |")
    add(
        f"| First post-revoke denial, p50 | {revocation['first_denial_p50']:.2f} ms | -- |"
    )
    add("")
    add(
        f"Measured over {revocation['samples']} runs, each revoking the root of a "
        "3-level chain (4 tokens). 'First post-revoke denial' is the full `/verify` "
        "round trip for a leaf token immediately after the revoke returned."
    )
    add("")

    add("### Item 8 -- checkpoint latency")
    add("")
    if "8" in measurements:
        add("```")
        for line in measurements["8"]:
            add(line)
        add("```")
    add(
        "Two figures are reported: through the full ASGI stack, and calling "
        "`DelegationEngine.verify()` directly. The PRD's target is qualified "
        "'excluding network', so the direct figure is the closer comparison; the HTTP "
        "figure is the honest upper bound for an in-process caller."
    )
    add("")

    add("## What each item actually proves")
    add("")
    add(
        "| # | The claim | How it is falsifiable |"
    )
    add("|---|-----------|----------------------|")
    add(
        "| 1 | A child can never hold a scope its parent lacks | Parametrized over the "
        "full non-subset matrix; a single 201 fails the suite |"
    )
    add(
        "| 2 | Any legitimate narrowing is honoured | Parametrized over every non-empty "
        "subset; also asserts `child.exp <= parent.exp` and depth limits |"
    )
    add(
        "| 3 | Revoking a root kills the whole subtree, durably | Verifies all 4 tokens "
        "are refused, then flushes the cache entirely and re-checks (fail-open guard) |"
    )
    add(
        "| 4 | Lineage cannot be fabricated | Chain is rebuilt from server records and "
        "cross-checked against the signed `delegation_chain` claim |"
    )
    add(
        "| 5 | The breaker opens on a genuine error spike | Synthetic spike, then "
        "asserts a *valid* token is refused with `circuit_open` |"
    )
    add(
        "| 6 | The audit log is tamper-evident | Five attack shapes: field mutation, "
        "decision flip, row deletion, forged row hash, backdating |"
    )
    add(
        "| 7 | No credential exists while approval is pending | Asserts the 202 body "
        "carries no token and no `token_record` row is created |"
    )
    add(
        "| 8 | Enforcement is cheap enough for the hot path | p50/p95/p99 reported at "
        "two layers, plus depth-scaling and buffer steady-state |"
    )
    add(
        "| 9 | A denied node's side effect never happens | Guarded nodes append to a "
        "list; the test asserts the list is empty after denial |"
    )
    add("")
    add("---")
    add("")
    add("Reproduce with:")
    add("")
    add("```bash")
    add("pip install -e \".[dev]\"")
    add("pip install -e ./langgraph_adf_adapter")
    add("pytest -q")
    add("python -m tests.generate_results")
    add("```")
    add("")

    return "\n".join(lines) + "\n"


def main() -> int:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    RESULTS_PATH.write_text(report, encoding="utf-8")
    print(f"\nWrote {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
