"""Dual-layer merge + view-scanning tests (mirror dual-layer/__tests__/*)."""

from __future__ import annotations

import base64

from aicomply import comply
from aicomply.classifier.dual_layer import (
    DualLayerOptions,
    _merge_verdicts,
    classify_dual_layer,
)
from aicomply.types import ClassifierResult


def _cr(verdict):
    return ClassifierResult(classifier="regex", verdict=verdict, violations=[])


def test_merge_both_clean_is_clean():
    assert _merge_verdicts(_cr("CLEAN"), _cr("CLEAN")) == "CLEAN"


def test_merge_either_violation_is_violation():
    assert _merge_verdicts(_cr("CLEAN"), _cr("VIOLATION")) == "VIOLATION"
    assert _merge_verdicts(_cr("VIOLATION"), _cr("CLEAN")) == "VIOLATION"


def test_merge_deny_wins():
    assert _merge_verdicts(_cr("VIOLATION"), _cr("DENY")) == "DENY"


def test_merge_regex_only_when_guard_none():
    assert _merge_verdicts(_cr("VIOLATION"), None) == "VIOLATION"
    assert _merge_verdicts(_cr("CLEAN"), None) == "CLEAN"


def test_regex_only_fallback_when_guard_unavailable():
    # No daemon running -> guard key absent, regex authoritative.
    res = classify_dual_layer("SSN 516-81-3086", DualLayerOptions(use_guard=False))
    assert res.verdict == "VIOLATION"
    assert "guard" not in res.classifier_results
    assert "regex" in res.classifier_results


def test_scans_compact_view_for_whitespace_evasion():
    res = comply("SSN 5 1 6-8 1-3 0 8 6", use_guard=False)
    types = {v.type for v in res.violations}
    assert "SSN" in types
    # at least one finding came from the compact view
    assert any(v.view == "compact" for v in res.violations)


def test_scans_base64_view():
    inner = "leaked key AKIA7IEO7LTOBPA48822 inside"
    blob = base64.b64encode(inner.encode()).decode()
    res = comply(f"payload: {blob}", use_guard=False)
    assert any(v.view == "decoded-base64" and v.type == "CREDENTIAL" for v in res.violations)


def test_normalization_metadata_attached():
    res = comply("２０６-０１-３７５９", use_guard=False)  # fullwidth SSN
    assert res.original_content == "２０６-０１-３７５９"
    assert res.normalized_content == "206-01-3759"
    assert any(s.transform == "nfkc" for s in res.normalizations)


def test_dedup_does_not_double_report_same_span():
    # A canonical SSN appears once even though normalized+compact both could match.
    res = comply("My SSN is 516-81-3086 today.", use_guard=False)
    ssns = [v for v in res.violations if v.type == "SSN"]
    assert len(ssns) == 1
