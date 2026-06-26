"""Integration ergonomics tests: decorator + LangChain optional import."""

from __future__ import annotations

import pytest

from aicomply.integrations import ComplianceViolation, guard_io, guard_output


def test_decorators_are_reexported_at_top_level():
    """`from aicomply import guard_io, ...` works and yields the same objects."""
    import aicomply

    assert aicomply.guard_io is guard_io
    assert aicomply.guard_output is guard_output
    assert aicomply.ComplianceViolation is ComplianceViolation
    for name in ("guard_io", "guard_output", "ComplianceViolation"):
        assert name in aicomply.__all__


def test_guard_output_raises_on_pii():
    @guard_output()  # default on_violation="raise"
    def answer() -> str:
        return "Your SSN is 516-81-3086."

    with pytest.raises(ComplianceViolation):
        answer()


def test_guard_output_allows_clean():
    @guard_output()
    def answer() -> str:
        return "All good, order 300843 shipped."

    assert answer() == "All good, order 300843 shipped."


def test_guard_output_redacts():
    @guard_output(on_violation="redact", use_guard=False)
    def answer() -> str:
        return "SSN 516-81-3086 here"

    out = answer()
    assert "516-81-3086" not in out
    assert "[REDACTED]" in out


def test_guard_output_allow_passes_through():
    @guard_output(on_violation="allow", use_guard=False)
    def answer() -> str:
        return "SSN 516-81-3086 here"

    assert answer() == "SSN 516-81-3086 here"


def test_guard_output_ignores_non_string_return():
    @guard_output()
    def numbers() -> int:
        return 42

    assert numbers() == 42


def test_guard_output_bare_usage_without_parens_raises_on_pii():
    # @guard_output (no parens) must behave like @guard_output() rather than
    # producing a cryptic TypeError when the wrapped function is called.
    @guard_output
    def answer() -> str:
        return "Your SSN is 516-81-3086."

    with pytest.raises(ComplianceViolation):
        answer()


def test_guard_output_bare_usage_allows_clean():
    @guard_output
    def answer() -> str:
        return "All good, order 300843 shipped."

    assert answer() == "All good, order 300843 shipped."


def test_guard_io_bare_usage_without_parens_checks_inputs():
    @guard_io
    def tool(text: str) -> str:
        return "ok"

    with pytest.raises(ComplianceViolation):
        tool("leak SSN 516-81-3086")


def test_guard_io_checks_inputs():
    @guard_io(use_guard=False)
    def tool(text: str) -> str:
        return "ok"

    with pytest.raises(ComplianceViolation):
        tool("leak SSN 516-81-3086")


def test_compliance_violation_message_lists_types():
    @guard_output(use_guard=False)
    def answer() -> str:
        return "SSN 516-81-3086 and AKIA7IEO7LTOBPA48822"

    try:
        answer()
    except ComplianceViolation as e:
        assert "SSN" in str(e) and "CREDENTIAL" in str(e)
    else:
        pytest.fail("expected ComplianceViolation")


def test_redact_text_handles_overlapping_spans():
    from aicomply.integrations.decorator import _redact_text
    from aicomply.types import Violation

    def v(s, e):
        return Violation(type="X", value="x", start=s, end=e, confidence=1.0,
                         classifier="regex", original_start=s, original_end=e)

    text = "0123456789ABCDEFGHIJ"
    # overlapping spans [2,10) and [6,14) must coalesce to one [2,14) redaction,
    # never produce debris like '[REDACTED]ACTED]' or drop a finding.
    out = _redact_text(text, [v(2, 10), v(6, 14)])
    assert out == "01[REDACTED]EFGHIJ"
    assert out.count("[REDACTED]") == 1  # coalesced, no debris from a double splice
    # identical spans collapse to a single redaction
    assert _redact_text(text, [v(2, 6), v(2, 6)]) == "01[REDACTED]6789ABCDEFGHIJ"
    # disjoint spans both redacted
    assert _redact_text(text, [v(0, 2), v(18, 20)]) == "[REDACTED]23456789ABCDEFGH[REDACTED]"


def test_langchain_handler_import_is_optional():
    # The factory must raise a clear, actionable error when langchain is absent,
    # NOT an obscure ImportError at module import time.
    import importlib.util

    from aicomply.integrations import langchain as lc_mod

    if importlib.util.find_spec("langchain_core") is None:
        with pytest.raises(ImportError, match="langchain-core"):
            lc_mod.AIComplyCallbackHandler()
    else:
        handler = lc_mod.AIComplyCallbackHandler()
        assert handler is not None
