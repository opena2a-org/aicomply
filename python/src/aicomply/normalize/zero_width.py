"""Strip zero-width and bidi-control characters (port of normalize/zero-width.ts).

These characters carry no semantic content for our detection patterns - stripping
them is lossless for our purposes and defeats e.g. inserting U+200B between SSN
digits. NOT stripped: U+00AD soft hyphen, combining marks (would break
legitimate accented prose).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .offset_map import OffsetMap, OffsetMapBuilder

STRIP_CODE_POINTS = frozenset(
    {
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2060,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0xFEFF,
    }
)

# A run of the characters in STRIP_CODE_POINTS.
_STRIPPED_RUN = re.compile(
    "[" + "".join(re.escape(chr(cp)) for cp in sorted(STRIP_CODE_POINTS)) + "]+"
)


@dataclass
class ZeroWidthStripResult:
    output: str
    offset_map: list[int]
    removed_count: int


@dataclass
class ZeroWidthStage:
    """A ZeroWidthStripResult with the offset map as an ``OffsetMap`` (see ``.offset_map``)."""

    output: str
    offset_map: OffsetMap
    removed_count: int


def strip_zero_width(text: str) -> ZeroWidthStripResult:
    stage = zero_width_stage(text)
    return ZeroWidthStripResult(
        output=stage.output, offset_map=list(stage.offset_map), removed_count=stage.removed_count
    )


def zero_width_stage(text: str) -> ZeroWidthStage:
    """strip_zero_width() with the map as an ``OffsetMap``.

    Each run between two runs of stripped characters goes to the output as one
    slice of the input.
    """
    parts: list[str] = []
    offsets = OffsetMapBuilder()
    removed = 0
    # text[copied:start] is a run that goes to the output as it is.
    copied = 0
    for run in _STRIPPED_RUN.finditer(text):
        start, end = run.span()
        parts.append(text[copied:start])
        offsets.copy(copied, start - copied)
        removed += end - start
        copied = end
    offsets.copy(copied, len(text) - copied)
    if removed == 0:
        return ZeroWidthStage(output=text, offset_map=offsets.finish(), removed_count=0)
    parts.append(text[copied:])
    return ZeroWidthStage(output="".join(parts), offset_map=offsets.finish(), removed_count=removed)
