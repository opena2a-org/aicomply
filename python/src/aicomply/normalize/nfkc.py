"""Unicode NFKC normalization with offset tracking (port of normalize/nfkc.ts).

NFKC folds compatibility variants to their canonical form (fullwidth digits ->
ASCII, math alphanumerics -> ASCII, ligatures, etc.), defeating the common
"use a fullwidth digit to evade an SSN regex" attack while preserving prose.
Conservative: it does NOT fold visually-similar-but-distinct glyphs (e.g.
Cyrillic 'a' U+0430 stays U+0430).

We normalize per code point so we can map each output code point back to the
source code point's offset.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass


@dataclass
class NFKCResult:
    output: str
    offset_map: list[int]  # offset_map[i] = source index where output[i] originated
    changed_count: int


def normalize_nfkc(text: str) -> NFKCResult:
    parts: list[str] = []
    offset_map: list[int] = []
    changed = 0

    for i, cp in enumerate(text):
        normalized = unicodedata.normalize("NFKC", cp)
        if normalized != cp:
            changed += 1
        parts.append(normalized)
        for _ in normalized:
            offset_map.append(i)

    return NFKCResult(output="".join(parts), offset_map=offset_map, changed_count=changed)
