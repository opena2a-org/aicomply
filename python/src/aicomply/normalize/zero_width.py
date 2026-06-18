"""Strip zero-width and bidi-control characters (port of normalize/zero-width.ts).

These characters carry no semantic content for our detection patterns - stripping
them is lossless for our purposes and defeats e.g. inserting U+200B between SSN
digits. NOT stripped: U+00AD soft hyphen (v1.1), combining marks (would break
legitimate accented prose).
"""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass
class ZeroWidthStripResult:
    output: str
    offset_map: list[int]
    removed_count: int


def strip_zero_width(text: str) -> ZeroWidthStripResult:
    parts: list[str] = []
    offset_map: list[int] = []
    removed = 0

    for i, cp in enumerate(text):
        if ord(cp) in STRIP_CODE_POINTS:
            removed += 1
            continue
        parts.append(cp)
        offset_map.append(i)

    return ZeroWidthStripResult(
        output="".join(parts), offset_map=offset_map, removed_count=removed
    )
