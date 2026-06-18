"""Bounded recursive extraction of Base64- and URL-encoded segments.

Port of normalize/encoded.ts. Attackers Base64-encode credentials or URL-encode
them as a trivial evasion. We extract candidates, decode them, and emit a
DecodedExtraction per successful decode for the dual-layer to scan.

Bounds (decision D-NORM-1): max recursion depth 2, min candidate length 24,
charset gate, and an ASCII-printable output gate (>= 90% printable). Binary
decodes are rejected.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

from .types import DecodedExtraction

MIN_CANDIDATE_LENGTH = 24
MAX_DEPTH = 2
PRINTABLE_MIN_RATIO = 0.9
MAX_LEFT_TRIM = 4

# Base64 character set; valid padding; we additionally gate to length >= 24.
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
# URL-encoded candidate: URL-safe run that includes percent-escapes.
_URL_PATTERN = re.compile(r"[A-Za-z0-9_\-.~!*'();:@&=+$,/?#\[\]%]+")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _count_percent_escapes(s: str) -> int:
    return len(_PERCENT_ESCAPE_RE.findall(s))


def _is_ascii_printable(s: str) -> bool:
    if len(s) == 0:
        return False
    printable = 0
    for ch in s:
        c = ord(ch)
        if (0x20 <= c <= 0x7E) or c in (0x09, 0x0A, 0x0D):
            printable += 1
    return printable / len(s) >= PRINTABLE_MIN_RATIO


def _try_base64_decode_aligned(candidate: str) -> str | None:
    if len(candidate) < MIN_CANDIDATE_LENGTH:
        return None
    if len(candidate) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(candidate, validate=False)
    except (binascii.Error, ValueError):
        return None
    # Mirror Node's Buffer.from(x,'base64').toString('utf8'): invalid UTF-8
    # sequences become U+FFFD, which then fails the printable / round-trip gates.
    decoded = raw.decode("utf-8", errors="replace")
    if not _is_ascii_printable(decoded):
        return None
    # Round-trip protects against decoder leniency (b64decode discards stray
    # chars). If it doesn't round-trip exactly, the candidate wasn't really Base64.
    round_trip = base64.b64encode(decoded.encode("utf-8")).decode("ascii")
    if round_trip.rstrip("=") != candidate.rstrip("="):
        return None
    return decoded


def _try_base64_decode(candidate: str) -> str | None:
    # Allow for misalignment from adjacent base64-charset bytes glued onto the
    # front (e.g. `//` from `wrapper://...`). Try as-is then 1..3 leading trims.
    for trim in range(MAX_LEFT_TRIM):
        trimmed = candidate[trim:]
        if len(trimmed) < MIN_CANDIDATE_LENGTH:
            return None
        result = _try_base64_decode_aligned(trimmed)
        if result is not None:
            return result
    return None


def _try_url_decode(candidate: str) -> str | None:
    decoded = unquote(candidate, encoding="utf-8", errors="replace")
    if decoded == candidate:
        return None
    if not _is_ascii_printable(decoded):
        return None
    return decoded


def _find_candidates(text: str) -> list[tuple[str, int, int, str]]:
    """Return (text, start, end, source) candidate tuples."""
    out: list[tuple[str, int, int, str]] = []

    for m in _BASE64_PATTERN.finditer(text):
        if len(m.group(0)) >= MIN_CANDIDATE_LENGTH:
            out.append((m.group(0), m.start(), m.end(), "decoded-base64"))

    for m in _URL_PATTERN.finditer(text):
        tok = m.group(0)
        if len(tok) < MIN_CANDIDATE_LENGTH:
            continue
        if _count_percent_escapes(tok) < 2:
            continue
        out.append((tok, m.start(), m.end(), "decoded-url"))

    return out


def extract_encoded(text: str) -> list[DecodedExtraction]:
    out: list[DecodedExtraction] = []

    for tok, start, end, source in _find_candidates(text):
        decoded = (
            _try_base64_decode(tok) if source == "decoded-base64" else _try_url_decode(tok)
        )
        if decoded is None:
            continue
        out.append(
            DecodedExtraction(
                decoded=decoded,
                original_start=start,
                original_end=end,
                source=source,  # type: ignore[arg-type]
                depth=1,
            )
        )

        if MAX_DEPTH < 2:
            continue
        # Depth-2: re-scan inside the decoded payload.
        for itok, _is, _ie, isource in _find_candidates(decoded):
            inner_decoded = (
                _try_base64_decode(itok)
                if isource == "decoded-base64"
                else _try_url_decode(itok)
            )
            if inner_decoded is None:
                continue
            out.append(
                DecodedExtraction(
                    decoded=inner_decoded,
                    original_start=start,
                    original_end=end,
                    source=isource,  # type: ignore[arg-type]
                    depth=2,
                )
            )

    return out
