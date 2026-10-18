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

from bisect import bisect_left
from dataclasses import dataclass

from .pack import PACK, PatternDefinition, PatternType
from .validators import luhn_check

__all__ = [
    "PATTERNS",
    "PatternDefinition",
    "PatternMatch",
    "PatternType",
    "drop_overlapping_repeats",
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
    return drop_overlapping_repeats(matches)


def drop_overlapping_repeats(matches: list[PatternMatch]) -> list[PatternMatch]:
    """``matches`` in their order, without each match whose range overlaps the
    range of an earlier kept match with the same value.

    ``scan_patterns`` passes its matches highest confidence first, pack order
    breaking a tie, so of two matches of one value at overlapping ranges the
    first in that order is kept.

    The kept matches of one value do not overlap one another, so ordered by
    start, then end, each ends at or before the start of the next. Of those that
    start before a match ends, the last in that order ends last, and the match
    overlaps one of them only if it overlaps that one. Each match is compared
    with that one kept match, found by binary search and a Fenwick tree, not
    with every kept match: that took time that grew with the square of the
    number of findings.
    """
    # The indices of the matches of each value, in match order.
    by_value: dict[str, list[int]] = {}
    for i, pm in enumerate(matches):
        by_value.setdefault(pm.value, []).append(i)

    kept = [False] * len(matches)
    # The place of a match among the matches of its value ordered by start, then end.
    place = [0] * len(matches)
    for indices in by_value.values():
        if len(indices) == 1:
            kept[indices[0]] = True
            continue
        ordered = sorted(indices, key=lambda i: (matches[i].start, matches[i].end))
        for p, index in enumerate(ordered):
            place[index] = p
        starts = [matches[index].start for index in ordered]
        # Fenwick tree over places: last_kept[k] is the last place of a kept match
        # among places k - (k & -k) to k - 1, or -1 when none of them is kept.
        last_kept = [-1] * (len(ordered) + 1)
        for index in indices:
            start, end = matches[index].start, matches[index].end
            # The matches at places 0 to starts_before - 1 start before this one ends.
            starts_before = bisect_left(starts, end)
            last = -1
            k = starts_before
            while k > 0:
                if last_kept[k] > last:
                    last = last_kept[k]
                k -= k & -k
            if last != -1 and matches[ordered[last]].end > start:
                continue
            kept[index] = True
            p = place[index]
            k = p + 1
            while k <= len(ordered):
                if last_kept[k] < p:
                    last_kept[k] = p
                k += k & -k
    return [pm for pm, keep in zip(matches, kept) if keep]
