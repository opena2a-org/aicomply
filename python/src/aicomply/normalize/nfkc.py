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

import re
import unicodedata
from dataclasses import dataclass

from .offset_map import OffsetMap, OffsetMapBuilder


@dataclass
class NFKCResult:
    output: str
    offset_map: list[int]  # offset_map[i] = source index where output[i] originated
    changed_count: int


@dataclass
class NFKCStage:
    """An NFKCResult with the offset map as an ``OffsetMap`` (see ``.offset_map``)."""

    output: str
    offset_map: OffsetMap
    changed_count: int


# An ASCII character is its own NFKC form, so only the others are normalized.
_NON_ASCII_RUN = re.compile(r"[^\x00-\x7f]+")


def normalize_nfkc(text: str) -> NFKCResult:
    stage = nfkc_stage(text)
    return NFKCResult(
        output=stage.output, offset_map=list(stage.offset_map), changed_count=stage.changed_count
    )


def nfkc_stage(text: str) -> NFKCStage:
    """normalize_nfkc() with the map as an ``OffsetMap``.

    Each code point that is not ASCII is normalized on its own, and each run of
    code points that are their own NFKC form goes to the output as one slice of
    the input.
    """
    parts: list[str] = []
    offsets = OffsetMapBuilder()
    changed = 0
    # text[copied:i] is a run that goes to the output as it is.
    copied = 0
    for run in _NON_ASCII_RUN.finditer(text):
        for i, cp in enumerate(run.group(), run.start()):
            normalized = unicodedata.normalize("NFKC", cp)
            if normalized == cp:
                continue
            # Each output character of a code point that NFKC changes points at it.
            parts.append(text[copied:i])
            offsets.copy(copied, i - copied)
            changed += 1
            parts.append(normalized)
            offsets.repeat(i, len(normalized))
            copied = i + 1
    offsets.copy(copied, len(text) - copied)
    if copied == 0:
        return NFKCStage(output=text, offset_map=offsets.finish(), changed_count=changed)
    parts.append(text[copied:])
    return NFKCStage(output="".join(parts), offset_map=offsets.finish(), changed_count=changed)
