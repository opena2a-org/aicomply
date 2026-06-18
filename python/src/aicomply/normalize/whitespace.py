"""Whitespace-compaction "compact" view (port of normalize/whitespace.ts).

Whitespace injection ("1 2 3 - 4 5 - 6 7 8 9") is a common evasion. Naively
stripping ALL whitespace breaks prose (word boundaries), so we strip a whitespace
run only when BOTH neighbors are token chars {digit, -, _, /, ., :} - the
characters that appear inside SSNs, PANs, IBANs, MRNs, NPIs, passport numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

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


def _is_whitespace(cp: int) -> bool:
    return cp in ASCII_WHITESPACE or cp in UNICODE_WHITESPACE


def _is_token_char(cp: int) -> bool:
    if 0x30 <= cp <= 0x39:  # digits 0-9
        return True
    # separators inside SSN/PAN/IBAN/MRN/NPI/passport numbers: - _ / . :
    return cp in (0x2D, 0x5F, 0x2F, 0x2E, 0x3A)


def build_compact_form(text: str) -> CompactFormResult:
    # (text, offset, cp) per code point. Offsets are code-point indices.
    code_points = [(ch, i, ord(ch)) for i, ch in enumerate(text)]

    parts: list[str] = []
    offset_map: list[int] = []
    removed = 0
    last_emitted_cp: int | None = None

    i = 0
    n = len(code_points)
    while i < n:
        ch, off, cp = code_points[i]
        if not _is_whitespace(cp):
            parts.append(ch)
            offset_map.append(off)
            last_emitted_cp = cp
            i += 1
            continue

        # Whitespace run: find the next non-whitespace code point.
        j = i + 1
        while j < n and _is_whitespace(code_points[j][2]):
            j += 1
        next_cp = code_points[j][2] if j < n else None

        strip_run = (
            last_emitted_cp is not None
            and next_cp is not None
            and _is_token_char(last_emitted_cp)
            and _is_token_char(next_cp)
        )

        if strip_run:
            removed += j - i
            i = j
        else:
            for k in range(i, j):
                wch, woff, _wcp = code_points[k]
                parts.append(wch)
                offset_map.append(woff)
            last_emitted_cp = code_points[j - 1][2]
            i = j

    return CompactFormResult(
        compact="".join(parts), offset_map=offset_map, removed_count=removed
    )
