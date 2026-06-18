"""Deterministic regex-based content classifier (port of classifier/regex/index.ts).

Accepts an optional view descriptor so the dual-layer can scan multiple content
views (normalized stream, compact form, Base64/URL-decoded extractions) and tag
each finding with its source view and best-effort original-content range.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...types import ClassifierResult, Violation, ViolationView
from .patterns import PatternMatch, luhn_check, scan_patterns

__all__ = ["classify_with_regex", "scan_patterns", "luhn_check", "PatternMatch"]


@dataclass
class ScanViewOptions:
    view: ViolationView = "normalized"
    offset_map: list[int] | None = None
    original_anchor: tuple[int, int] | None = None  # (start, end)


def _redact(value: str) -> str:
    """Partial-redact a matched value for safe logging (port of redact())."""
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "..." + value[-2:]


def classify_with_regex(
    content: str, options: ScanViewOptions | None = None
) -> ClassifierResult:
    opts = options or ScanViewOptions()
    matches = scan_patterns(content)
    view = opts.view

    violations: list[Violation] = []
    for m in matches:
        v = Violation(
            type=m.type,
            value=_redact(m.value),
            start=m.start,
            end=m.end,
            confidence=m.confidence,
            classifier="regex",
            view=view,
        )
        if opts.original_anchor is not None:
            v.original_start = opts.original_anchor[0]
            v.original_end = opts.original_anchor[1]
        elif opts.offset_map is not None:
            start_idx = opts.offset_map[m.start] if m.start < len(opts.offset_map) else None
            last_in = m.end - 1
            end_idx = opts.offset_map[last_in] if 0 <= last_in < len(opts.offset_map) else None
            if start_idx is not None:
                v.original_start = start_idx
            if end_idx is not None:
                v.original_end = end_idx + 1
        else:
            v.original_start = m.start
            v.original_end = m.end
        violations.append(v)

    return ClassifierResult(
        classifier="regex",
        verdict="CLEAN" if len(violations) == 0 else "VIOLATION",
        violations=violations,
    )
