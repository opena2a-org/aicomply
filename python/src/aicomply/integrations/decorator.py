"""A ``@guard_output`` decorator to wrap an agent function's I/O.

Mirrors the AIM Python SDK decorator ergonomics: drop one line above the function
that produces text bound for an LLM (or returns LLM output to a user) and any
non-CLEAN content is blocked (raises) or redacted, before it leaves the boundary.

    from aicomply.integrations import guard_output

    @guard_output()                 # raise on any PII/credential egress
    def answer(user_msg: str) -> str:
        return call_llm(user_msg)

    @guard_output(on_violation="redact")   # mask findings in-place instead
    def answer2(user_msg: str) -> str:
        return call_llm(user_msg)
"""

from __future__ import annotations

import functools
from typing import Callable, Literal, TypeVar

from .. import ComplyResult, comply
from ..types import Violation

F = TypeVar("F", bound=Callable[..., object])

OnViolation = Literal["raise", "redact", "allow"]


class ComplianceViolation(Exception):
    """Raised by ``guard_output(on_violation="raise")`` when content is not CLEAN."""

    def __init__(self, result: ComplyResult):
        self.result = result
        types = ", ".join(sorted({v.type for v in result.violations})) or "unknown"
        super().__init__(
            f"aicomply blocked egress: verdict={result.verdict}; "
            f"detected {len(result.violations)} finding(s) [{types}]"
        )


def _redact_text(text: str, violations: list[Violation]) -> str:
    """Best-effort in-place redaction using each finding's original-content range.

    Findings carry ``original_start`` / ``original_end`` into the pre-normalization
    content, so we can splice over the source spans. Spans are applied
    right-to-left so earlier offsets stay valid. Findings without a usable range
    (e.g. guard-layer whole-content hits) fall back to leaving the text unchanged
    for that span - the verdict already tells the caller it was not CLEAN.
    """
    spans = sorted(
        (
            (v.original_start, v.original_end)
            for v in violations
            if v.original_start is not None
            and v.original_end is not None
            and v.original_end > v.original_start
        ),
        key=lambda s: s[0],
        reverse=True,
    )
    redacted = text
    for start, end in spans:
        if 0 <= start < end <= len(redacted):
            redacted = redacted[:start] + "[REDACTED]" + redacted[end:]
    return redacted


def guard_output(
    on_violation: OnViolation = "raise",
    *,
    use_guard: bool = True,
) -> Callable[[F], F]:
    """Decorate a function whose string return value should be compliance-checked.

    :param on_violation: ``"raise"`` (default) raises :class:`ComplianceViolation`;
        ``"redact"`` returns the masked string; ``"allow"`` returns unchanged
        (audit-only - inspect via logging hooks).
    :param use_guard: forwarded to :func:`aicomply.comply`.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            output = func(*args, **kwargs)
            if not isinstance(output, str):
                return output
            result = comply(output, use_guard=use_guard)
            if result.verdict == "CLEAN":
                return output
            if on_violation == "raise":
                raise ComplianceViolation(result)
            if on_violation == "redact":
                return _redact_text(output, result.violations)
            return output  # "allow"

        return wrapper  # type: ignore[return-value]

    return decorator


def guard_io(
    on_violation: OnViolation = "raise",
    *,
    use_guard: bool = True,
    check_inputs: bool = True,
) -> Callable[[F], F]:
    """Like :func:`guard_output` but also scans string positional/keyword inputs.

    Useful for wrapping a tool that both receives and returns text, so injected
    PII is caught on the way in as well as on the way out.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            if check_inputs:
                for value in list(args) + list(kwargs.values()):
                    if isinstance(value, str):
                        res = comply(value, use_guard=use_guard)
                        if res.verdict != "CLEAN":
                            if on_violation == "raise":
                                raise ComplianceViolation(res)
                            # redact/allow on inputs is the caller's risk; we only
                            # hard-stop on raise. Pass through otherwise.
            output = func(*args, **kwargs)
            if not isinstance(output, str):
                return output
            result = comply(output, use_guard=use_guard)
            if result.verdict == "CLEAN":
                return output
            if on_violation == "raise":
                raise ComplianceViolation(result)
            if on_violation == "redact":
                return _redact_text(output, result.violations)
            return output

        return wrapper  # type: ignore[return-value]

    return decorator
