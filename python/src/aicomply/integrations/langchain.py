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
instead, including the text blocks of a chat message whose content is a list.
Where a finding cannot be masked in what the caller receives, ``"redact"``
raises :class:`ComplianceViolation` as ``"raise"`` does: a finding with no range
in the text (a Guard-layer finding covers the whole completion), or a
``stream()`` / ``astream()`` call.

The check runs when the generation ends. A model that streams has already
yielded its chunks to a ``stream()`` caller by then, so the exception arrives
after the last chunk; use ``invoke()`` where an unchecked completion must not
reach the caller.
"""

from __future__ import annotations

from typing import Any

from .. import comply
from ..types import Violation
from .decorator import ComplianceViolation, OnViolation, _has_range_in, _redaction_spans


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


def _is_streamed(generation: Any) -> bool:
    """Whether ``stream()`` or ``astream()`` has already yielded the generation's text.

    Those two pass ``on_llm_end`` a ``GenerationChunk`` or ``ChatGenerationChunk``
    merged from the chunks the caller has received. ``invoke()`` and ``batch()``
    pass the ``Generation`` or ``ChatGeneration`` whose text they return.
    """
    from langchain_core.outputs import ChatGenerationChunk, GenerationChunk

    return isinstance(generation, (GenerationChunk, ChatGenerationChunk))


def _mask(piece: str, offset: int, spans: list[list[int]]) -> str:
    """Mask the part of ``piece`` that ``spans`` cover, ``piece`` starting at ``offset``.

    Each span becomes one marker, placed in the piece where the span starts, so
    masking each piece of a text and joining them gives the masked text.
    """
    end_of_piece = offset + len(piece)
    out: list[str] = []
    position = offset
    for start, end in spans:
        if end <= offset or start >= end_of_piece:
            continue
        out.append(piece[position - offset : max(start, offset) - offset])
        if start >= offset:
            out.append("[REDACTED]")
        position = min(end, end_of_piece)
    out.append(piece[position - offset :])
    return "".join(out)


def _mask_blocks(content: list, text: str, spans: list[list[int]]) -> list | None:
    """Mask the text blocks of list message content, or None if they do not spell ``text``.

    LangChain joins string items and the ``text`` of text blocks to make the
    generation text that was checked, so the same walk maps each finding back
    to the blocks it falls in.
    """
    masked = list(content)
    offset = 0
    for index, block in enumerate(content):
        if isinstance(block, str):
            piece = block
        elif (
            isinstance(block, dict)
            and block.get("type") in ("text", None)
            and isinstance(block.get("text"), str)
        ):
            piece = block["text"]
        else:
            continue
        if text[offset : offset + len(piece)] != piece:
            return None
        masked_piece = _mask(piece, offset, spans)
        masked[index] = masked_piece if isinstance(block, str) else {**block, "text": masked_piece}
        offset += len(piece)
    return masked if offset == len(text) else None


def _redact_generation(generation: Any, text: str, violations: list[Violation]) -> bool:
    """Mask the findings wherever the generation holds ``text``; False if it cannot.

    A completion model returns ``generation.text``. A chat model returns
    ``generation.message``, whose content is a string or a list of blocks. False
    means the caller would receive a finding unmasked: a finding has no range in
    the text, ``stream()`` has already yielded the text, or the message holds it
    in a shape this function does not rewrite.
    """
    if _is_streamed(generation):
        return False
    if not all(_has_range_in(v, text) for v in violations):
        return False
    spans = _redaction_spans(text, violations)
    updates: list[tuple[Any, str, Any]] = [(generation, "text", _mask(text, 0, spans))]
    message = getattr(generation, "message", None)
    if message is not None:
        content = getattr(message, "content", None)
        if isinstance(content, str) and content == text:
            updates.append((message, "content", _mask(content, 0, spans)))
        elif isinstance(content, list):
            masked = _mask_blocks(content, text, spans)
            if masked is None:
                return False
            updates.append((message, "content", masked))
        else:
            return False
    for target, attribute, value in updates:
        try:
            setattr(target, attribute, value)
        except (AttributeError, TypeError, ValueError):
            return False
    return True


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
            # "redact" raises when it cannot mask a finding, so it needs it too.
            self.raise_error = on_violation != "allow"

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
                    if self._on_violation == "redact" and not _redact_generation(
                        generation, text, result.violations
                    ):
                        raise ComplianceViolation(result)
                    # "allow": audit-only, leave as-is.

    return _AIComplyCallbackHandler()


def AIComplyCallbackHandler(  # noqa: N802 - class-like factory, intentional name
    on_violation: OnViolation = "raise", *, use_guard: bool = True
):
    """Class-style alias for :func:`make_aicomply_callback_handler`."""
    return make_aicomply_callback_handler(on_violation, use_guard=use_guard)
