"""Architectural boundary checks, run as part of the primary gate.

A check that is never exercised is indistinguishable from a check that does not
work, so each test below also confirms the detector fires on a deliberately
broken sample. Otherwise a refactor could silently neuter the whole file and
every test would still be green.
"""

from __future__ import annotations

import textwrap

import pytest

from tests import check_boundaries as cb


class TestRepositoryIsCompliant:
    def test_no_unverified_decode_on_enforcement_path(self):
        violations = cb.check_no_unverified_decode_on_enforcement_path()
        assert violations == [], "\n\n".join(v.render() for v in violations)

    def test_models_are_backend_portable(self):
        violations = cb.check_models_are_backend_portable()
        assert violations == [], "\n\n".join(v.render() for v in violations)

    def test_admin_key_comparison_is_constant_time(self):
        violations = cb.check_admin_key_comparison_is_constant_time()
        assert violations == [], "\n\n".join(v.render() for v in violations)

    def test_audit_log_is_append_only(self):
        violations = cb.check_audit_log_is_append_only()
        assert violations == [], "\n\n".join(v.render() for v in violations)

    def test_no_insecure_secret_defaults(self):
        violations = cb.check_no_insecure_secret_defaults()
        assert violations == [], "\n\n".join(v.render() for v in violations)

    def test_all_checks_pass(self):
        violations = cb.run_all()
        assert violations == [], "\n\n".join(v.render() for v in violations)


class TestChecksActuallyDetectViolations:
    """Meta-tests: prove the detectors are not vacuous."""

    @pytest.fixture
    def fake_service(self, tmp_path, monkeypatch):
        """A throwaway package tree the checks can be pointed at."""
        service = tmp_path / "checkpoint_service"
        (service / "engine").mkdir(parents=True)
        (service / "routes").mkdir(parents=True)
        (service / "models").mkdir(parents=True)
        monkeypatch.setattr(cb, "SERVICE", service)
        monkeypatch.setattr(cb, "REPO_ROOT", tmp_path)
        return service

    def test_detects_unverified_decode(self, fake_service):
        (fake_service / "engine" / "delegation_engine.py").write_text(
            textwrap.dedent(
                """
                def verify(token):
                    claims = engine.decode_unverified(token)
                    return claims["jti"]
                """
            ),
            encoding="utf-8",
        )
        violations = cb.check_no_unverified_decode_on_enforcement_path()
        assert len(violations) == 1
        assert "attacker-controlled" in violations[0].why

    def test_ignores_the_word_in_a_docstring(self, fake_service):
        """The check must not fire on prose that merely mentions the ban."""
        (fake_service / "engine" / "delegation_engine.py").write_text(
            '"""Never call decode_unverified() here."""\nx = 1\n',
            encoding="utf-8",
        )
        assert cb.check_no_unverified_decode_on_enforcement_path() == []

    def test_detects_jsonb_column(self, fake_service):
        (fake_service / "models" / "audit.py").write_text(
            textwrap.dedent(
                """
                from sqlalchemy import Column
                from sqlalchemy.dialects.postgresql import JSONB

                detail = Column(JSONB)
                """
            ),
            encoding="utf-8",
        )
        violations = cb.check_models_are_backend_portable()
        assert len(violations) >= 1
        assert any("JSONB" in v.location or "JSONB" in v.what for v in violations)

    def test_ignores_jsonb_mentioned_in_a_docstring(self, fake_service):
        """Regression: models/base.py documents why JSONB is banned."""
        (fake_service / "models" / "base.py").write_text(
            '"""Use JSON rather than Postgres JSONB for portability."""\nx = 1\n',
            encoding="utf-8",
        )
        assert cb.check_models_are_backend_portable() == []

    def test_detects_plain_equality_on_admin_key(self, fake_service):
        (fake_service / "routes" / "deps.py").write_text(
            textwrap.dedent(
                """
                def require_admin(supplied, settings):
                    if supplied == settings.admin_api_key:
                        return True
                    return False
                """
            ),
            encoding="utf-8",
        )
        violations = cb.check_admin_key_comparison_is_constant_time()
        assert len(violations) == 1
        assert "compare_digest" in violations[0].fix

    def test_accepts_compare_digest(self, fake_service):
        (fake_service / "routes" / "deps.py").write_text(
            textwrap.dedent(
                """
                import secrets

                def require_admin(supplied, settings):
                    return secrets.compare_digest(supplied, settings.admin_api_key)
                """
            ),
            encoding="utf-8",
        )
        assert cb.check_admin_key_comparison_is_constant_time() == []

    def test_detects_audit_log_mutation(self, fake_service):
        (fake_service / "engine" / "audit_logger.py").write_text(
            textwrap.dedent(
                """
                from sqlalchemy import update
                from models import AuditLog

                def fix_history(session, row_id):
                    session.execute(update(AuditLog).where(AuditLog.id == row_id))
                """
            ),
            encoding="utf-8",
        )
        violations = cb.check_audit_log_is_append_only()
        assert len(violations) >= 1
        assert "hash chain" in violations[0].why

    def test_detects_hardcoded_secret_default(self, fake_service):
        (fake_service / "config.py").write_text(
            textwrap.dedent(
                """
                class Settings:
                    jwt_secret: str = "dev-secret-do-not-ship"
                    admin_api_key: str = ""
                """
            ),
            encoding="utf-8",
        )
        violations = cb.check_no_insecure_secret_defaults()
        assert len(violations) == 1
        assert "jwt_secret" in violations[0].what


class TestTestSuiteMutationsAreLocalised:
    """The audit-mutation check must not flag the tests that need to tamper.

    tests/test_audit_integrity.py deliberately corrupts rows to prove the chain
    detects it. That is correct there and forbidden in service code, so the check
    is scoped to checkpoint_service/ only. This test pins that scoping so nobody
    'helpfully' widens it and then disables the check when it goes off.
    """

    def test_tamper_tests_exist_and_are_not_scanned(self):
        tamper_test = cb.REPO_ROOT / "tests" / "test_audit_integrity.py"
        source = tamper_test.read_text(encoding="utf-8")
        assert "update(AuditLog)" in source, "the tamper tests no longer tamper"
        assert cb.check_audit_log_is_append_only() == []

    def test_checks_are_scoped_to_the_service_package(self):
        assert cb.SERVICE.name == "checkpoint_service"
        assert cb.SERVICE.is_dir()
