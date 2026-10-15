"""Named post-match validators referenced by the pattern pack.

Port of classifier/regex/validators.ts. The pack (``pack/patterns.json``) holds
the regexes as data; checks a regex cannot express portably (checksums, prefix
tables, and the "contains a digit" test that used to be a lookahead) live here
as code, and a pack entry names one by its key. Every runtime implements the
same names with the same semantics; the conformance suite proves it per case.
"""

from __future__ import annotations

import re
from typing import Callable

Validator = Callable[[str], bool]


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
    if len(cleaned) < 13 or len(cleaned) > 19:
        return False
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


def _validate_npi(match: str) -> bool:
    cleaned = re.sub(r"\s", "", match)
    if not re.fullmatch(r"\d{10}", cleaned, flags=re.ASCII):
        return False
    # NPI Luhn uses prefix 80840 prepended to the 10-digit NPI.
    return luhn_check("80840" + cleaned)


_EMPTY_ASSIGNMENT_TARGET = re.compile(r"[A-Z][A-Z0-9_]*=", re.ASCII)


def _not_empty_assignment_target(value: str) -> bool:
    """Reject a captured value that is really the NEXT KEY of an empty assignment.

    ``OPENAI_API_KEY=`` on one line followed by ``ANTHROPIC_API_KEY=`` on the
    next used to report the second key's name as a secret. Keyed on UPPER_SNAKE
    plus a single trailing ``=``: base64 values are mixed-case, so a legitimate
    value ending in one padding character is untouched, and an all-caps hex
    secret (no trailing ``=``) still reports.
    """
    return _EMPTY_ASSIGNMENT_TARGET.fullmatch(value) is None


def _contains_digit(value: str) -> bool:
    """Require at least one ASCII digit (real MRNs are never an English word)."""
    return any("0" <= ch <= "9" for ch in value)


#: The ``validator`` value of a pack entry that runs no post-match check. It is
#: a name rather than null so every entry states its check explicitly.
NO_VALIDATOR = "none"

#: Validator names a pack entry may reference, mapped to their implementation.
#: The names are part of the pack contract: every runtime implements the same
#: set, with the same semantics.
VALIDATORS: dict[str, Validator] = {
    # SSN area, group and serial rules (no 000, 666 or 9xx area, no 00 group, no 0000 serial).
    "ssnArea": _validate_ssn,
    # Card number (PAN): 13-19 digits, Luhn checksum and a known IIN prefix.
    "luhn": _validate_pan,
    # IBAN: length 15-34 and the ISO 13616 mod-97 check.
    "mod97": _validate_iban,
    # NPI: exactly 10 digits, Luhn over the 80840 prefix.
    "npiLuhn": _validate_npi,
    "notEmptyAssignmentTarget": _not_empty_assignment_target,
    "containsDigit": _contains_digit,
}
