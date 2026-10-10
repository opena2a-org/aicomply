"""Deterministic regex scan for sensitive data classification.

Port of classifier/regex/patterns.ts. The patterns themselves are data in the
shared pattern pack, compiled once by ``.pack``; named validators live in
``.validators``. This module only runs them. JS->Python notes:

* JS ``/.../g`` exec loop -> ``finditer`` (non-overlapping, like the ``exec``
  loop). JS ``match.index`` -> ``m.start()``; ``match[1] || match[0]`` ->
  ``m.group(1) or m.group(0)``.
* JS ``String.prototype.trim`` + an anchored ``RegExp.test`` -> ``strip`` +
  ``fullmatch``, so ``$`` cannot match before a trailing newline as Python's
  ``search`` would allow.
"""

from __future__ import annotations

from dataclasses import dataclass

from .pack import PACK, PatternDefinition, PatternType
from .validators import luhn_check

__all__ = [
    "PATTERNS",
    "PatternDefinition",
    "PatternMatch",
    "PatternType",
    "is_env_var_reference",
    "luhn_check",
    "scan_patterns",
]


@dataclass
class PatternMatch:
    type: PatternType
    value: str
    start: int
    end: int
    confidence: float


#: Compiled patterns, in pack order. Pack order is scan and tie-break order.
PATTERNS: list[PatternDefinition] = PACK.patterns


def is_env_var_reference(value: str) -> bool:
    """True when the value is a reference to a credential, not the credential.

    ``process.env.OPENAI_API_KEY`` is the remediated shape that ``opena2a
    protect`` rewrites a hardcoded key into; reporting it makes two commands
    contradict each other and breaks CI on correctly-fixed code. The forms are
    the pack's ``referenceForms``, each anchored against the whole captured
    value, so a value that merely contains a reference-shaped substring
    (``process.envXABC...``) is still a finding.
    """
    trimmed = value.strip()
    return any(form.fullmatch(trimmed) for form in PACK.reference_forms)


def scan_patterns(content: str) -> list[PatternMatch]:
    """Scan content against all patterns and return validated, de-overlapped matches."""
    matches: list[PatternMatch] = []

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(content):
            full_match = match.group(0)
            group1 = match.group(1) if match.lastindex else None
            captured = group1 if group1 else full_match
            # An env-var reference names a secret without carrying one. Skipped
            # here, not per pattern, because any keyword rule can capture one.
            if is_env_var_reference(captured):
                continue
            if pattern.validate is not None and not pattern.validate(captured):
                continue
            matches.append(
                PatternMatch(
                    type=pattern.type,
                    value=captured,
                    start=match.start(),
                    end=match.start() + len(full_match),
                    confidence=pattern.confidence,
                )
            )

    # Deduplicate overlapping matches: higher confidence wins. Stable sort to
    # mirror V8's stable Array.sort for equal-confidence ties.
    matches.sort(key=lambda pm: -pm.confidence)
    deduped: list[PatternMatch] = []
    for pm in matches:
        overlaps = any(
            pm.start < d.end and pm.end > d.start and pm.value == d.value for d in deduped
        )
        if not overlaps:
            deduped.append(pm)
    return deduped
