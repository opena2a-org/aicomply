"""Shared test setup (mirrors jest.setup.js in the TypeScript package).

Every test is isolated from a nanomind-daemon a developer may be running on the
default address. The adapter honours MOCK_NANOMIND_URL only when NODE_ENV is
"test" or "development", so both are set, with the override pointing at a
closed port. Tests that want adapter success start their own server and pass
its URL through ``base_url`` or set MOCK_NANOMIND_URL themselves.

A test that sets NODE_ENV to another value (to prove the override is ignored)
falls back to the default address, so the adapter's default is pointed at the
closed port too.
"""

from __future__ import annotations

import pytest

from aicomply.classifier.guard_client import nanomind_adapter

_CLOSED_PORT_URL = "http://127.0.0.1:1"


@pytest.fixture(autouse=True)
def _isolate_from_local_nanomind_daemon(monkeypatch):
    monkeypatch.setenv("NODE_ENV", "test")
    monkeypatch.setenv("MOCK_NANOMIND_URL", _CLOSED_PORT_URL)
    monkeypatch.setattr(nanomind_adapter, "DEFAULT_NANOMIND_DAEMON_URL", _CLOSED_PORT_URL)
