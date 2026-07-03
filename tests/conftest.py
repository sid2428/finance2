"""Shared fixtures. Each test gets a fresh, fully-wired AEGIS system so state
stores (velocity, ledger, step-up) never leak across tests."""

from __future__ import annotations

import pytest

from aegis.runtime import build_system
from aegis.testkit import build_bundle


@pytest.fixture()
def system():
    return build_system()


@pytest.fixture()
def make_bundle(system):
    def _make(**kwargs):
        return build_bundle(system.keyring, **kwargs)
    return _make
