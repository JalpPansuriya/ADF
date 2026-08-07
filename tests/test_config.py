"""F01: configuration and secret hardening.

The service must refuse to boot with weak or placeholder secrets. A guessable
HS256 key lets anyone forge a token with arbitrary scopes, which voids every other
guarantee in the system -- so this is enforced at startup, not documented.
"""

from __future__ import annotations

import pathlib

import pytest

from checkpoint_service.config import (
    ConfigurationError,
    Settings,
    load_sensitive_scopes,
)
from tests.conftest import ADMIN_KEY, JWT_SECRET, PII_SALT, build_settings


def _settings(**overrides) -> Settings:
    values = dict(
        admin_api_key=ADMIN_KEY,
        jwt_secret=JWT_SECRET,
        pii_salt=PII_SALT,
    )
    values.update(overrides)
    return Settings(**values)


class TestSecretValidation:
    def test_valid_secrets_pass(self):
        _settings().validate_secrets()

    @pytest.mark.parametrize(
        "field", ["admin_api_key", "jwt_secret", "pii_salt"]
    )
    def test_missing_secret_refuses_boot(self, field):
        settings = _settings(**{field: ""})
        with pytest.raises(ConfigurationError, match="is not set"):
            settings.validate_secrets()

    @pytest.mark.parametrize(
        "value",
        [
            "change-me-admin-key-min-16-chars",
            "changeme-secret-value-that-is-long-enough",
            "your-secret-key-goes-here-abcdefgh",
            "TODO-replace-this-value-later-1234",
        ],
    )
    def test_placeholder_secret_refuses_boot(self, value):
        """The values shipped in .env.example must not be usable."""
        settings = _settings(jwt_secret=value)
        with pytest.raises(ConfigurationError, match="placeholder"):
            settings.validate_secrets()

    def test_short_secret_refuses_boot(self):
        settings = _settings(jwt_secret="tooshort")
        with pytest.raises(ConfigurationError, match="at least 32 characters"):
            settings.validate_secrets()

    def test_short_admin_key_refuses_boot(self):
        settings = _settings(admin_api_key="abc123")
        with pytest.raises(ConfigurationError, match="at least 16 characters"):
            settings.validate_secrets()

    def test_error_lists_every_problem_at_once(self):
        """An operator should see all failures, not fix them one restart at a time."""
        settings = _settings(admin_api_key="", jwt_secret="", pii_salt="")
        with pytest.raises(ConfigurationError) as exc:
            settings.validate_secrets()
        message = str(exc.value)
        assert "ADF_ADMIN_API_KEY" in message
        assert "ADF_JWT_SECRET" in message
        assert "ADF_PII_SALT" in message
        # And it should tell them how to generate real ones.
        assert "token_urlsafe" in message

    def test_env_example_values_are_all_rejected(self):
        """Directly guards against shipping .env.example as .env."""
        example = pathlib.Path(__file__).resolve().parent.parent / ".env.example"
        values: dict[str, str] = {}
        for line in example.read_text(encoding="utf-8").splitlines():
            if line.startswith("ADF_") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
        settings = _settings(
            admin_api_key=values["ADF_ADMIN_API_KEY"],
            jwt_secret=values["ADF_JWT_SECRET"],
            pii_salt=values["ADF_PII_SALT"],
        )
        with pytest.raises(ConfigurationError):
            settings.validate_secrets()


class TestSensitiveScopes:
    def test_loaded_from_yaml(self):
        settings = build_settings()
        assert "send_email" in settings.sensitive_scopes
        assert "spend_money" in settings.sensitive_scopes
        assert "delete_data" in settings.sensitive_scopes
        assert "read_calendar" not in settings.sensitive_scopes

    def test_missing_file_is_empty_not_an_error(self, tmp_path):
        assert load_sensitive_scopes(tmp_path / "nope.yaml") == frozenset()

    def test_malformed_file_is_a_hard_error(self, tmp_path):
        """Silently ignoring a broken policy file would disable the approval gate."""
        bad = tmp_path / "bad.yaml"
        bad.write_text("sensitive_scopes: not-a-list\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="list of strings"):
            load_sensitive_scopes(bad)

    def test_non_mapping_file_is_a_hard_error(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="YAML mapping"):
            load_sensitive_scopes(bad)


class TestListParsing:
    def test_csv_env_values_split(self):
        settings = _settings(
            guardrail_exempt_agents="a, b ,c", cors_origins="http://x,http://y"
        )
        assert settings.guardrail_exempt_agents == ["a", "b", "c"]
        assert settings.cors_origins == ["http://x", "http://y"]

    def test_native_list_passes_through(self):
        settings = _settings(guardrail_exempt_agents=["a", "b"])
        assert settings.guardrail_exempt_agents == ["a", "b"]


class TestThresholdValidation:
    @pytest.mark.parametrize("value", [0.0, -0.1, 1.5])
    def test_invalid_error_rate_rejected(self, value):
        with pytest.raises(Exception):
            _settings(circuit_error_rate_threshold=value)

    def test_valid_error_rate_accepted(self):
        assert _settings(circuit_error_rate_threshold=1.0)


class TestExemptionRegistry:
    def test_raw_name_matches(self):
        settings = _settings(guardrail_exempt_agents=["bench-agent"])
        assert settings.is_exempt("bench-agent") is True
        assert settings.is_exempt("other-agent") is False
        assert settings.is_exempt(None) is False

    def test_resolved_subject_id_matches_after_registration(self):
        settings = _settings(guardrail_exempt_agents=["bench-agent"])
        assert settings.is_exempt("agent:uuid-1") is False
        settings.register_exempt_subject("bench-agent", "agent:uuid-1")
        assert settings.is_exempt("agent:uuid-1") is True

    def test_non_exempt_identifier_is_not_registered(self):
        settings = _settings(guardrail_exempt_agents=["bench-agent"])
        settings.register_exempt_subject("ordinary-agent", "agent:uuid-2")
        assert settings.is_exempt("agent:uuid-2") is False
