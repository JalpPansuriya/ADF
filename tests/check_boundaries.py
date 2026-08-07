"""Executable architectural boundary checks.

HARNESS_ENGINEERING Part 7: a rule written in prose but not enforced by a check
will eventually be violated -- not maliciously, but because agents copy the
patterns they see. These are the machine-checkable versions of the hard
constraints in agent-files/AGENTS.md.

Run standalone::

    python -m tests.check_boundaries

Also executed as part of the suite via tests/test_boundaries.py.

Note on implementation: these parse the AST rather than grepping raw text. A grep
for "JSONB" matches the docstring in models/base.py that *explains* why JSONB is
banned -- a check that fires on its own documentation gets muted, and a muted
check protects nothing.
"""

from __future__ import annotations

import ast
import pathlib
from typing import NamedTuple

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVICE = REPO_ROOT / "checkpoint_service"


class Violation(NamedTuple):
    """An architectural rule that has been broken.

    Carries WHAT/WHY/FIX because an agent-oriented error message needs to be
    actionable on its own (HARNESS_ENGINEERING Part 6).
    """

    check: str
    location: str
    what: str
    why: str
    fix: str

    def render(self) -> str:
        return (
            f"[{self.check}]\n"
            f"  WHAT: {self.what} ({self.location})\n"
            f"  WHY:  {self.why}\n"
            f"  FIX:  {self.fix}"
        )


def _iter_python(root: pathlib.Path):
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _names_used(tree: ast.AST) -> set[str]:
    """Identifiers and attribute names that appear as *code*, not in strings."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
    return found


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def check_no_unverified_decode_on_enforcement_path() -> list[Violation]:
    """Hard Constraint 1: never read a claim before verifying the signature."""
    guarded = [
        SERVICE / "engine" / "delegation_engine.py",
        SERVICE / "routes" / "tokens.py",
        SERVICE / "engine" / "revocation.py",
        SERVICE / "engine" / "guardrails.py",
    ]
    violations: list[Violation] = []
    for path in guarded:
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if "decode_unverified" in _names_used(tree):
            violations.append(
                Violation(
                    check="unverified-decode",
                    location=str(path.relative_to(REPO_ROOT)),
                    what="decode_unverified() is called on the enforcement path",
                    why=(
                        "an unverified JWT payload is entirely attacker-controlled, so "
                        "any claim read from it (including jti) cannot be trusted "
                        "(AGENTS.md Hard Constraint 1)"
                    ),
                    fix=(
                        "use TokenEngine.decode(), which verifies signature, issuer and "
                        "required claims first; reserve decode_unverified() for "
                        "dashboard/diagnostic rendering of already-persisted rows"
                    ),
                )
            )
    return violations


def check_models_are_backend_portable() -> list[Violation]:
    """Hard Constraint 9: models must compile on SQLite and Postgres alike."""
    banned = {"JSONB", "ARRAY", "UUID", "TSVECTOR", "HSTORE", "JSONPATH"}
    violations: list[Violation] = []
    for path, tree in _iter_python(SERVICE / "models"):
        used = _names_used(tree)
        for name in sorted(banned & used):
            violations.append(
                Violation(
                    check="backend-portability",
                    location=f"{path.relative_to(REPO_ROOT)} uses {name}",
                    what=f"Postgres-specific column type {name} in models/",
                    why=(
                        "the eval harness runs on SQLite, which cannot compile these "
                        "types, so the primary gate would break "
                        "(AGENTS.md Hard Constraint 9)"
                    ),
                    fix="use JSON instead of JSONB, String instead of UUID",
                )
            )
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "dialects" in node.module:
                    violations.append(
                        Violation(
                            check="backend-portability",
                            location=f"{path.relative_to(REPO_ROOT)}:{node.lineno}",
                            what=f"dialect-specific import: {node.module}",
                            why="ties the schema to one backend and breaks the SQLite gate",
                            fix="use the generic sqlalchemy types instead",
                        )
                    )
    return violations


def check_admin_key_comparison_is_constant_time() -> list[Violation]:
    """Hard Constraint 8: `==` on a secret is a timing side channel."""
    violations: list[Violation] = []
    for path, tree in _iter_python(SERVICE):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                continue
            operands = [node.left, *node.comparators]
            for operand in operands:
                name = (
                    operand.attr
                    if isinstance(operand, ast.Attribute)
                    else operand.id
                    if isinstance(operand, ast.Name)
                    else None
                )
                if name in {"admin_api_key", "jwt_secret", "x_admin_key"}:
                    violations.append(
                        Violation(
                            check="constant-time-secret-compare",
                            location=f"{path.relative_to(REPO_ROOT)}:{node.lineno}",
                            what=f"secret {name!r} compared with ==/!=",
                            why=(
                                "byte-by-byte comparison short-circuits, leaking the "
                                "shared prefix through response timing "
                                "(AGENTS.md Hard Constraint 8)"
                            ),
                            fix="use secrets.compare_digest(supplied, expected)",
                        )
                    )
    return violations


def check_audit_log_is_append_only() -> list[Violation]:
    """Hard Constraint 7: never UPDATE or DELETE an audit row in service code."""
    violations: list[Violation] = []
    for path, tree in _iter_python(SERVICE):
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name not in {"update", "delete"}:
                continue
            segment = ast.get_source_segment(source, node) or ""
            if "AuditLog" in segment:
                violations.append(
                    Violation(
                        check="append-only-audit",
                        location=f"{path.relative_to(REPO_ROOT)}:{node.lineno}",
                        what=f"{name}() targeting AuditLog in service code",
                        why=(
                            "mutating or removing a row breaks the hash chain and "
                            "destroys the tamper-evidence guarantee "
                            "(AGENTS.md Hard Constraint 7)"
                        ),
                        fix=(
                            "append a new corrective event via AuditLogger.log() "
                            "instead of editing history"
                        ),
                    )
                )
    return violations


def check_no_insecure_secret_defaults() -> list[Violation]:
    """Hard Constraint 6: secrets must have no usable default."""
    violations: list[Violation] = []
    path = SERVICE / "config.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign) or node.value is None:
            continue
        target = node.target
        if not isinstance(target, ast.Name):
            continue
        if target.id not in {"admin_api_key", "jwt_secret", "pii_salt"}:
            continue
        default = node.value
        if isinstance(default, ast.Constant) and default.value == "":
            continue  # empty default is fine; validate_secrets() rejects it
        violations.append(
            Violation(
                check="no-insecure-defaults",
                location=f"{path.relative_to(REPO_ROOT)}:{node.lineno}",
                what=f"{target.id} has a non-empty default value",
                why=(
                    "a guessable signing key or admin key lets anyone forge tokens "
                    "with arbitrary scopes, voiding every other guarantee "
                    "(AGENTS.md Hard Constraint 6)"
                ),
                fix='default to "" and let Settings.validate_secrets() refuse to boot',
            )
        )
    return violations


CHECKS = (
    check_no_unverified_decode_on_enforcement_path,
    check_models_are_backend_portable,
    check_admin_key_comparison_is_constant_time,
    check_audit_log_is_append_only,
    check_no_insecure_secret_defaults,
)


def run_all() -> list[Violation]:
    violations: list[Violation] = []
    for check in CHECKS:
        violations.extend(check())
    return violations


def main() -> int:
    violations = run_all()
    if not violations:
        print(f"All {len(CHECKS)} architectural boundary checks passed.")
        return 0
    print(f"{len(violations)} boundary violation(s):\n")
    for violation in violations:
        print(violation.render())
        print()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
