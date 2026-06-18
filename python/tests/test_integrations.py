"""Integration ergonomics tests: decorator + LangChain optional import."""

from __future__ import annotations

import pytest

from aicomply.integrations import ComplianceViolation, guard_io, guard_output


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
