"""LangChain integration -- block PII/credential egress from an LLM in ~5 lines.

LangChain is an OPTIONAL dependency. This module imports ``langchain_core`` lazily
inside the handler so the base ``aicomply`` package has zero hard dependencies;
import this module only when you actually use LangChain (``pip install
aicomply[langchain]``).

    from langchain_openai import ChatOpenAI
    from aicomply.integrations.langchain import AIComplyCallbackHandler

    llm = ChatOpenAI(callbacks=[AIComplyCallbackHandler()])
    llm.invoke("Summarize this ticket: ...")   # raises if the LLM emits PII

The handler inspects each LLM generation as it completes. On a non-CLEAN verdict
the default ``on_violation="raise"`` raises
:class:`aicomply.integrations.decorator.ComplianceViolation` out of the model
call (``invoke``, ``ainvoke``, ``batch``), so the completion never reaches the
caller. ``on_violation="redact"`` masks the findings in the returned text
instead; a chat message whose content is a list of blocks rather than a string
is returned unchanged.

The check runs when the generation ends. A model that streams has already
yielded its chunks to a ``stream()`` caller by then.
"""

from __future__ import annotations

from typing import Any

from .. import comply
from .decorator import ComplianceViolation, OnViolation, _redact_text


def _resolve_base_handler() -> type:
    """Import LangChain's BaseCallbackHandler lazily; raise a clear error if absent."""
    try:
        from langchain_core.callbacks.base import BaseCallbackHandler
    except ImportError as err:  # pragma: no cover - exercised only without langchain
        raise ImportError(
            "AIComplyCallbackHandler requires langchain-core. "
            "Install it with: pip install 'aicomply[langchain]'"
        ) from err
    return BaseCallbackHandler


def _redact_generation(generation: Any, redacted: str) -> None:
    """Write the redacted text into a generation in place, where supported.

    A completion model returns ``generation.text``. A chat model returns
    ``generation.message``, so string message content is rewritten as well.
    """
    targets = [(generation, "text")]
    message = getattr(generation, "message", None)
    if isinstance(getattr(message, "content", None), str):
        targets.append((message, "content"))
    for target, attribute in targets:
        try:
            setattr(target, attribute, redacted)
        except (AttributeError, TypeError):
            pass


def make_aicomply_callback_handler(
    on_violation: OnViolation = "raise", *, use_guard: bool = True
):
    """Construct an AIComply LangChain callback handler.

    Factory function so the LangChain base class is only resolved at call time
    (keeping the import optional). Returns a ``BaseCallbackHandler`` instance.
    """
    base = _resolve_base_handler()

    class _AIComplyCallbackHandler(base):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__()
            self._on_violation = on_violation
            self._use_guard = use_guard
            # Unless a handler sets raise_error, LangChain logs and drops its
            # exception and the model call returns the completion anyway.
            self.raise_error = on_violation == "raise"

        def on_llm_end(self, response: Any, **kwargs: Any) -> None:
            # response is a langchain_core.outputs.LLMResult.
            for generation_list in getattr(response, "generations", []) or []:
                for generation in generation_list:
                    text = getattr(generation, "text", None)
                    if not isinstance(text, str) or not text:
                        continue
                    result = comply(text, use_guard=self._use_guard)
                    if result.verdict == "CLEAN":
                        continue
                    if self._on_violation == "raise":
                        raise ComplianceViolation(result)
                    if self._on_violation == "redact":
                        _redact_generation(generation, _redact_text(text, result.violations))
                    # "allow": audit-only, leave as-is.

    return _AIComplyCallbackHandler()


def AIComplyCallbackHandler(  # noqa: N802 - class-like factory, intentional name
    on_violation: OnViolation = "raise", *, use_guard: bool = True
):
    """Class-style alias for :func:`make_aicomply_callback_handler`."""
    return make_aicomply_callback_handler(on_violation, use_guard=use_guard)
