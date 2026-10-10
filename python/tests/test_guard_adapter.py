"""NanoMind daemon adapter tests (mirror guard-client/__tests__/nanomind-adapter)."""

from __future__ import annotations

import json

import pytest

from aicomply.classifier.guard_client.nanomind_adapter import (
    _validate_infer_response,
    classify_with_nanomind_daemon,
    map_infer_response_to_classifier_result,
)


def _ok_response(attack_class="", confidence=0.5):
    return {
        "intent": "INTENT_CHECK",
        "result": "ok",
        "confidence": confidence,
        "attackClass": attack_class,
        "latencyMs": 3,
        "modelVersion": "0.5.0",
    }


def test_validate_accepts_well_formed():
    assert _validate_infer_response(_ok_response()) is not None


def test_validate_rejects_bad_shapes():
    assert _validate_infer_response(None) is None
    assert _validate_infer_response("nope") is None
    assert _validate_infer_response({**_ok_response(), "confidence": 2}) is None
    assert _validate_infer_response({**_ok_response(), "attackClass": "made_up"}) is None
    assert _validate_infer_response({**_ok_response(), "modelVersion": ""}) is None
    # bool must not satisfy the numeric confidence check
    assert _validate_infer_response({**_ok_response(), "confidence": True}) is None


def test_map_benign_is_clean():
    r = map_infer_response_to_classifier_result(_ok_response(""), 10)
    assert r.verdict == "CLEAN"
    assert r.violations == []


def test_map_below_threshold_is_clean():
    r = map_infer_response_to_classifier_result(
        _ok_response("prompt_injection", 0.5), 10
    )
    assert r.verdict == "CLEAN"


def test_map_above_threshold_is_violation_without_leaking_evidence():
    resp = _ok_response("exfiltration_pattern", 0.95)
    resp["evidence"] = "attacker-controlled <script>"
    r = map_infer_response_to_classifier_result(resp, 10)
    assert r.verdict == "VIOLATION"
    assert r.violations[0].type == "exfiltration_pattern"
    # evidence/remediation must never reach the violation value (trust boundary)
    assert r.violations[0].value == "***GUARD***"


def test_classify_returns_none_when_daemon_unreachable():
    # Nothing listening on this port -> connection refused -> None (silent fallback).
    from aicomply.classifier.guard_client.nanomind_adapter import NanoMindAdapterOptions

    out = classify_with_nanomind_daemon(
        "SSN 516-81-3086",
        NanoMindAdapterOptions(base_url="http://127.0.0.1:1", timeout_ms=300),
    )
    assert out is None


def test_health_probe_on_unreachable_daemon_is_recorded(recorded_urls: list[str]):
    # The probe passes urlopen a URL string, not a Request; the fixture records both.
    from aicomply.classifier.guard_client.nanomind_adapter import is_nanomind_daemon_available

    assert is_nanomind_daemon_available() is False
    assert recorded_urls == ["http://127.0.0.1:1/health"]


def test_classify_skips_empty_input():
    assert classify_with_nanomind_daemon("   ") is None


def _start_recording_daemon():
    import http.server
    import threading

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("content-length", 0))
            received.append((self.path, self.rfile.read(length)))
            payload = json.dumps(_ok_response()).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}", received


@pytest.mark.parametrize("node_env", ["production", None, "staging"])
def test_mock_url_is_ignored_outside_test_and_development(monkeypatch, node_env):
    from aicomply.classifier.guard_client.nanomind_adapter import (
        DEFAULT_NANOMIND_DAEMON_URL,
        NanoMindAdapterOptions,
        _resolve_base_url,
    )

    server, url, received = _start_recording_daemon()
    try:
        monkeypatch.setenv("MOCK_NANOMIND_URL", url)
        if node_env is None:
            monkeypatch.delenv("NODE_ENV", raising=False)
        else:
            monkeypatch.setenv("NODE_ENV", node_env)
        assert _resolve_base_url(NanoMindAdapterOptions()) == DEFAULT_NANOMIND_DAEMON_URL
        classify_with_nanomind_daemon(
            "SSN 516-81-3086", NanoMindAdapterOptions(timeout_ms=300)
        )
        assert received == []
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("node_env", ["test", "development"])
def test_mock_url_is_honoured_in_test_and_development(monkeypatch, node_env):
    server, url, received = _start_recording_daemon()
    try:
        monkeypatch.setenv("MOCK_NANOMIND_URL", url)
        monkeypatch.setenv("NODE_ENV", node_env)
        out = classify_with_nanomind_daemon("content")
        assert out is not None and out.verdict == "CLEAN"
        assert [path for path, _ in received] == ["/v1/infer"]
    finally:
        server.shutdown()
        server.server_close()


def test_explicit_base_url_wins_over_mock_url(monkeypatch):
    from aicomply.classifier.guard_client.nanomind_adapter import (
        NanoMindAdapterOptions,
        _resolve_base_url,
    )

    monkeypatch.setenv("MOCK_NANOMIND_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("NODE_ENV", "test")
    opts = NanoMindAdapterOptions(base_url="http://127.0.0.1:47201")
    assert _resolve_base_url(opts) == "http://127.0.0.1:47201"


# The address a developer's own nanomind-daemon listens on. conftest.py keeps
# every test away from it, so fixture content never reaches a real daemon.
_LOCAL_DAEMON_URL = "http://127.0.0.1:47200"


def test_tests_without_base_url_never_reach_a_local_daemon():
    from aicomply.classifier.guard_client.nanomind_adapter import (
        NanoMindAdapterOptions,
        _resolve_base_url,
    )

    assert _resolve_base_url(NanoMindAdapterOptions()) != _LOCAL_DAEMON_URL


@pytest.mark.parametrize("node_env", ["production", None, "staging"])
def test_tests_outside_test_mode_never_reach_a_local_daemon(monkeypatch, node_env):
    from aicomply.classifier.guard_client.nanomind_adapter import (
        NanoMindAdapterOptions,
        _resolve_base_url,
    )

    if node_env is None:
        monkeypatch.delenv("NODE_ENV", raising=False)
    else:
        monkeypatch.setenv("NODE_ENV", node_env)
    assert _resolve_base_url(NanoMindAdapterOptions()) != _LOCAL_DAEMON_URL
