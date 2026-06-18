"""Public API tests (mirror __tests__/comply-registry.test.ts, core subset)."""

from __future__ import annotations

import pytest

from aicomply import ComplyResult, comply


def test_empty_content_is_clean_with_audit_fields():
    res = comply("", use_guard=False)
    assert isinstance(res, ComplyResult)
    assert res.verdict == "CLEAN"
    assert res.violations == []
    assert res.original_content == ""
    assert res.normalized_content == ""
    assert res.normalizations == []
    assert res.classifier_results["regex"].verdict == "CLEAN"


def test_non_string_content_raises_typeerror():
    with pytest.raises(TypeError):
        comply(12345)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        comply(None)  # type: ignore[arg-type]


def test_clean_content_safe_to_forward():
    res = comply("The weather is nice. Order 300843 shipped.", use_guard=False)
    assert res.verdict == "CLEAN"


def test_violation_content():
    res = comply("SSN 516-81-3086 and AKIA7IEO7LTOBPA48822", use_guard=False)
    assert res.verdict == "VIOLATION"
    types = {v.type for v in res.violations}
    assert "SSN" in types and "CREDENTIAL" in types


def test_to_dict_uses_camelcase_for_wire_parity():
    res = comply("SSN 516-81-3086", use_guard=False)
    d = res.to_dict()
    assert d["verdict"] == "VIOLATION"
    assert "classifierResults" in d  # camelCase, not classifier_results
    assert "originalContent" in d
    finding = d["violations"][0]
    assert "originalStart" in finding and "originalEnd" in finding


def test_values_in_result_are_masked():
    res = comply("key AKIA7IEO7LTOBPA48822", use_guard=False)
    cred = next(v for v in res.violations if v.type == "CREDENTIAL")
    assert "AKIA7IEO7LTOBPA48822" not in cred.value
