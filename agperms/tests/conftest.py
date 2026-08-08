"""Shared fixtures for the agperms suite."""

from __future__ import annotations

import pytest

from agperms import Config, Firewall, MemoryStorage

ROOT_SCOPES = ["read_calendar", "write_calendar", "read_email", "web_search"]


@pytest.fixture
def config() -> Config:
    """A fixed signing key so failures are reproducible, plus generous limits.

    Rate limits are raised because several tests loop hundreds of times; the
    limiter itself is exercised directly in test_guardrails.py with tight limits.
    """
    return Config(
        jwt_secret="test-secret-not-for-production-0123456789abcdef",
        pii_salt="test-salt",
        rate_limit_delegate_per_min=100_000,
        rate_limit_verify_per_min=100_000,
        rate_limit_action_per_min=100_000,
        circuit_volume_ceiling=1_000_000,
    )


@pytest.fixture
def storage() -> MemoryStorage:
    return MemoryStorage()


@pytest.fixture
def fw(config: Config, storage: MemoryStorage) -> Firewall:
    return Firewall(config=config, storage=storage)


@pytest.fixture
def root(fw: Firewall):
    """A depth-0 capability holding every non-sensitive demo scope."""
    return fw.mint_root(subject="alice", scopes=ROOT_SCOPES)
