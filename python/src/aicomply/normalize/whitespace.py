"""Whitespace-compaction "compact" view (port of normalize/whitespace.ts).

Whitespace injection ("1 2 3 - 4 5 - 6 7 8 9") is a common evasion. Naively
stripping ALL whitespace breaks prose (word boundaries), so we strip a whitespace
run only when BOTH neighbors are token chars {digit, -, _, /, ., :} - the
characters that appear inside SSNs, PANs, IBANs, MRNs, NPIs, passport numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .offset_map import OffsetMap, OffsetMapBuilder

ASCII_WHITESPACE = frozenset({0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20})
UNICODE_WHITESPACE = frozenset(
    {
        0x00A0,
        0x1680,
        0x2000,
        0x2001,
        0x2002,
        0x2003,
        0x2004,
        0x2005,
        0x2006,
        0x2007,
        0x2008,
        0x2009,
        0x200A,
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    }
)


@dataclass
class CompactFormResult:
    compact: str
    offset_map: list[int]  # offset_map[i] = index in INPUT where compact[i] originated
    removed_count: int


@dataclass
class CompactStage:
    """A CompactFormResult with the offset map as an ``OffsetMap`` (see ``.offset_map``)."""

    compact: str
    offset_map: OffsetMap
    removed_count: int


# Characters that can sit on either side of a stripped whitespace run: the
# digits 0-9 and the separators inside SSN/PAN/IBAN/MRN/NPI/passport numbers.
_TOKEN = "[0-9" + re.escape("-_/.:") + "]"
_WHITESPACE = (
    "[" + "".join(re.escape(chr(cp)) for cp in sorted(ASCII_WHITESPACE | UNICODE_WHITESPACE)) + "]"
)
# A whitespace run (group 1) with a token character on each side. The run is
# all the whitespace between them, as a token character is not whitespace.
# The character after the run is only looked at, so it can also be the one
# before the next run.
_STRIPPED_RUN = re.compile(f"{_TOKEN}({_WHITESPACE}+)(?={_TOKEN})")


def build_compact_form(text: str) -> CompactFormResult:
    stage = compact_stage(text)
    return CompactFormResult(
        compact=stage.compact, offset_map=list(stage.offset_map), removed_count=stage.removed_count
    )


def compact_stage(text: str) -> CompactStage:
    """build_compact_form() with the map as an ``OffsetMap``.

    Each run between two stripped whitespace runs goes to the output as one
    slice of the input.
    """
    parts: list[str] = []
    offsets = OffsetMapBuilder()
    removed = 0
    # text[copied:start] is a run that goes to the output as it is.
    copied = 0
    for run in _STRIPPED_RUN.finditer(text):
        start, end = run.span(1)
        parts.append(text[copied:start])
        offsets.copy(copied, start - copied)
        removed += end - start
        copied = end
    offsets.copy(copied, len(text) - copied)
    if removed == 0:
        return CompactStage(compact=text, offset_map=offsets.finish(), removed_count=0)
    parts.append(text[copied:])
    return CompactStage(compact="".join(parts), offset_map=offsets.finish(), removed_count=removed)
