"""Deterministic regex patterns for sensitive data classification.

Port of classifier/regex/patterns.ts. JS->Python regex translation notes:

* All patterns compile with ``re.ASCII`` so ``\\d`` / ``\\b`` / ``\\w`` and
  IGNORECASE case-folding match JavaScript's ASCII semantics exactly (JS ``\\d``
  is ``[0-9]``; Python's default ``\\d`` is Unicode-aware and would diverge on
  e.g. Arabic-Indic digits). NFKC normalization runs *before* the regex layer,
  so legitimate fullwidth digits are already folded to ASCII.
* JS ``/.../gi`` -> ``re.IGNORECASE`` + ``finditer`` (non-overlapping, like the
  ``exec`` loop). JS ``match.index`` -> ``m.start()``; ``match[1] || match[0]``
  -> ``m.group(1) or m.group(0)``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

PatternType = Literal[
    "SSN", "PAN", "CUI", "CREDENTIAL", "IBAN", "PASSPORT", "MRN", "NPI"
]


@dataclass
class PatternMatch:
    type: PatternType
    value: str
    start: int
    end: int
    confidence: float


def luhn_check(digits: str) -> bool:
    """Luhn checksum for card numbers and NPI."""
    cleaned = re.sub(r"[\s-]", "", digits)
    if not re.fullmatch(r"\d+", cleaned, flags=re.ASCII):
        return False

    total = 0
    alternate = False
    for ch in reversed(cleaned):
        n = int(ch)
        if alternate:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alternate = not alternate
    return total % 10 == 0


def _validate_ssn(match: str) -> bool:
    parts = match.split("-")
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area == "000" or area == "666":
        return False
    if int(area) >= 900:
        return False
    if group == "00":
        return False
    if serial == "0000":
        return False
    return True


def _validate_iban(match: str) -> bool:
    cleaned = re.sub(r"\s", "", match).upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric = ""
    for ch in rearranged:
        code = ord(ch)
        if 65 <= code <= 90:  # A-Z -> 10..35
            numeric += str(code - 55)
        else:
            numeric += ch
    remainder = 0
    for digit in numeric:
        remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def _validate_pan(match: str) -> bool:
    cleaned = re.sub(r"[\s-]", "", match)
    if not luhn_check(cleaned):
        return False
    first = cleaned[0]
    first_two = cleaned[:2]
    if first == "4":  # Visa
        return True
    if 51 <= int(first_two) <= 55:  # Mastercard
        return True
    if 2221 <= int(cleaned[:4]) <= 2720:  # Mastercard 2-series
        return True
    if first_two == "34" or first_two == "37":  # Amex
        return True
    if cleaned.startswith("6011") or first_two == "65":  # Discover
        return True
    if 644 <= int(cleaned[:3]) <= 649:  # Discover
        return True
    return False


def _validate_pan_with_length(match: str) -> bool:
    cleaned = re.sub(r"[\s-]", "", match)
    if len(cleaned) < 13 or len(cleaned) > 19:
        return False
    return _validate_pan(match)


def _validate_npi(match: str) -> bool:
    cleaned = re.sub(r"\s", "", match)
    if not re.fullmatch(r"\d{10}", cleaned, flags=re.ASCII):
        return False
    # NPI Luhn uses prefix 80840 prepended to the 10-digit NPI.
    return luhn_check("80840" + cleaned)


@dataclass
class PatternDefinition:
    type: PatternType
    regex: re.Pattern
    confidence: float
    validate: Callable[[str], bool] | None = None


_A = re.ASCII
_AI = re.ASCII | re.IGNORECASE

PATTERNS: list[PatternDefinition] = [
    PatternDefinition("SSN", re.compile(r"\b(\d{3}-\d{2}-\d{4})\b", _A), 0.95, _validate_ssn),
    PatternDefinition(
        "PAN", re.compile(r"\b(\d[\d -]{11,22}\d)\b", _A), 0.9, _validate_pan_with_length
    ),
    PatternDefinition(
        "CUI",
        re.compile(
            r"\b(CUI//SP-[A-Z-]+|CONTROLLED\s+UNCLASSIFIED\s+INFORMATION|"
            r"FOR\s+OFFICIAL\s+USE\s+ONLY|CUI//[A-Z-]+)\b",
            _AI,
        ),
        0.99,
    ),
    PatternDefinition("CREDENTIAL", re.compile(r"\b(AKIA[0-9A-Z]{16})\b", _A), 0.98),
    # AWS secret access key. The secret is a 40-char base64 string with no
    # distinctive prefix (unlike the AKIA id above), so it is matched only in an
    # aws_secret_access_key assignment context to avoid flagging every 40-char
    # hash/id. Parity with the TS patterns.ts AWS secret rule.
    PatternDefinition(
        "CREDENTIAL",
        re.compile(
            r"(?:aws[_-]?)?secret[_-]?access[_-]?key[\"']?\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+]{40})['\"]?",
            _AI,
        ),
        0.9,
    ),
    # Anthropic API key (sk-ant-apiNN-...). Provider keys appear bare in tool
    # output and transcripts, not only in `key=` assignments, so they need a
    # dedicated rule. Adapted from @opena2a/credential-patterns; parity with the
    # TS patterns.ts CREDENTIAL block. No leading \b — the distinctive
    # 'sk-ant-api' prefix is FP-proof on its own, and dropping the anchor stops
    # a key surviving an adjacent word char (e.g. a prepended '_sk-ant-...').
    PatternDefinition(
        "CREDENTIAL", re.compile(r"(sk-ant-api\d{2}-[A-Za-z0-9_-]{20,})", _A), 0.98
    ),
    # OpenAI project-scoped key (sk-proj-...). Char class widened to [_-] vs the
    # canonical [A-Za-z0-9]{20,}: real project keys carry '-'/'_' separators.
    PatternDefinition(
        "CREDENTIAL", re.compile(r"(sk-proj-[A-Za-z0-9_-]{20,})", _A), 0.98
    ),
    # OpenRouter key (sk-or-v1-...)
    PatternDefinition(
        "CREDENTIAL", re.compile(r"(sk-or-v1-[A-Za-z0-9]{48,})", _A), 0.98
    ),
    # OpenAI legacy secret key (sk- followed by 48+ alnum). Broadest rule, so the
    # lowest confidence: a 48-char hash/ID prefixed with 'sk-' can false-positive.
    # Unlike the specific rules above it KEEPS a leading \b to suppress the common
    # English-word FPs (risk-/disk-/task- + long token). The early '-' in
    # sk-ant-/sk-proj-/sk-or-v1- means those are caught by their specific rules.
    PatternDefinition("CREDENTIAL", re.compile(r"\b(sk-[A-Za-z0-9]{48,})", _A), 0.85),
    PatternDefinition("CREDENTIAL", re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b", _A), 0.98),
    PatternDefinition(
        "CREDENTIAL", re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b", _A), 0.98
    ),
    PatternDefinition(
        "CREDENTIAL", re.compile(r"Bearer\s+([A-Za-z0-9._~+/=-]{20,})", _A), 0.85
    ),
    PatternDefinition(
        "CREDENTIAL",
        re.compile(
            r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9._~+/=-]{16,})['\"]?",
            _AI,
        ),
        0.8,
    ),
    PatternDefinition(
        "IBAN",
        re.compile(
            r"\b([A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4})\b",
            _A,
        ),
        0.85,
        _validate_iban,
    ),
    PatternDefinition(
        "PASSPORT",
        re.compile(r"(?:passport|travel\s+document)[:\s#-]*\b([A-Z]{1,2}\d{6,9})\b", _AI),
        0.75,
    ),
    PatternDefinition(
        "MRN",
        re.compile(r"\bMRN[:\s#-]*(?=[A-Z0-9]*\d)([A-Z0-9]{6,12})\b", _AI),
        0.9,
    ),
    PatternDefinition(
        "NPI", re.compile(r"\bNPI[:\s#-]*(\d{10})\b", _AI), 0.85, _validate_npi
    ),
]


def scan_patterns(content: str) -> list[PatternMatch]:
    """Scan content against all patterns and return validated, de-overlapped matches."""
    matches: list[PatternMatch] = []

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(content):
            full_match = match.group(0)
            group1 = match.group(1) if match.lastindex else None
            captured = group1 if group1 else full_match
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
