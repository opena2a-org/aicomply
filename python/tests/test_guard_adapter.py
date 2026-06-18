"""NanoMind daemon adapter tests (mirror guard-client/__tests__/nanomind-adapter)."""

from __future__ import annotations

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


def test_classify_skips_empty_input():
    assert classify_with_nanomind_daemon("   ") is None
