"""Pattern pack loader: the single construction site of compiled patterns.

Port of classifier/regex/pack.ts. The detection regexes are data in
``aicomply/pack/patterns.json``, a byte-identical copy of the repository's
``pack/patterns.json`` that every runtime reads. This module checks the file
against the pack contract and compiles it; nothing else in the package holds a
detection pattern literal.

The loader fails closed: a missing, malformed or non-portable pack raises at
import time rather than leaving the classifier running with no patterns, which
would report every input as CLEAN.

Every regex compiles with ``re.ASCII`` so ``\\d`` / ``\\b`` / ``\\w`` and
IGNORECASE case-folding match JavaScript's ASCII semantics (JS ``\\d`` is
``[0-9]``; Python's default ``\\d`` is Unicode-aware and would diverge on e.g.
Arabic-Indic digits). ``\\s`` is the known gap in the other direction:
JavaScript's ``\\s`` also matches Unicode separators such as U+2028 and U+1680,
which ``re.ASCII`` does not, so a value set off from its keyword by one of
those separators is reported by the TypeScript runtime and not by this one.
NFKC normalization runs *before* the regex layer, so legitimate fullwidth
digits are already folded to ASCII; it leaves those separators unchanged.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Literal, cast

from ...types import PackIdentity
from .validators import VALIDATORS, Validator

PatternType = Literal["SSN", "PAN", "CUI", "CREDENTIAL", "IBAN", "PASSPORT", "MRN", "NPI"]

PATTERN_TYPES: tuple[str, ...] = (
    "SSN",
    "PAN",
    "CUI",
    "CREDENTIAL",
    "IBAN",
    "PASSPORT",
    "MRN",
    "NPI",
)

#: The pack schema this loader reads. A different value is refused.
PACK_SCHEMA_VERSION = 1

_ID = re.compile(r"[a-z0-9][a-z0-9-]*", re.ASCII)
_SEMVER = re.compile(r"\d+\.\d+\.\d+", re.ASCII)


@dataclass
class PatternDefinition:
    id: str
    type: PatternType
    regex: re.Pattern[str]
    confidence: float
    validate: Validator | None = None


@dataclass
class CompiledPack:
    version: str
    #: SHA-256 (hex) of the exact pack file bytes.
    sha256: str
    patterns: list[PatternDefinition] = field(default_factory=list)
    #: Anchored forms of a value that names a secret without carrying one.
    reference_forms: list[re.Pattern[str]] = field(default_factory=list)


class PackError(ValueError):
    """The pattern pack does not satisfy the pack contract."""


def non_portable_construct(source: str) -> str | None:
    """Return the first construct outside the portable regex subset, or None.

    The subset is syntax that JavaScript, Python ``re`` and RE2 (Go) all
    accept: no lookaround, no backreferences, no named groups, and no inline
    modifier groups (case-insensitivity is the entry's ``flags`` field).
    Accepting the syntax does not make the engines agree on every input (see
    the module docstring on ``\\s``); the conformance suite is what asserts
    agreement, case by case.
    """
    in_class = False
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\":
            if i + 1 >= n:
                return "trailing backslash"
            nxt = source[i + 1]
            if "1" <= nxt <= "9":
                return "backreference"
            if nxt == "k":
                return "named backreference"
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c == "(" and source[i + 1 : i + 2] == "?":
            kind = source[i + 2 : i + 3]
            if kind == ":":
                i += 1
                continue
            if kind in ("=", "!"):
                return "lookahead"
            if kind == "<":
                after = source[i + 3 : i + 4]
                return "lookbehind" if after in ("=", "!") else "named group"
            if kind == "P":
                return "named group"
            return "inline modifier group"
        i += 1
    return None


def _fail(message: str) -> PackError:
    return PackError(f"aicomply pattern pack: {message}")


def _compile(where: str, source: object, flags: int) -> re.Pattern[str]:
    if not isinstance(source, str) or not source:
        raise _fail(f"{where}: regex must be a non-empty string")
    construct = non_portable_construct(source)
    if construct is not None:
        raise _fail(f"{where}: regex uses a {construct}, which is outside the portable subset")
    try:
        return re.compile(source, flags)
    except re.error as err:
        raise _fail(f"{where}: regex does not compile ({err})") from err


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def compile_pack(data: bytes) -> CompiledPack:
    """Validate and compile pack file bytes.

    Exposed so tests can prove each contract rule refuses a bad pack; production
    code uses the module-level ``PACK``.
    """
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise _fail(f"not valid JSON ({err})") from err
    if not isinstance(doc, dict):
        raise _fail("top level must be an object")
    schema = doc.get("schemaVersion")
    if not _is_number(schema) or schema != PACK_SCHEMA_VERSION:
        raise _fail(f"schemaVersion {schema} is not supported (expected {PACK_SCHEMA_VERSION})")
    version = doc.get("packVersion")
    if not isinstance(version, str) or _SEMVER.fullmatch(version) is None:
        raise _fail("packVersion must be a MAJOR.MINOR.PATCH string")
    entries = doc.get("patterns")
    if not isinstance(entries, list) or not entries:
        raise _fail("patterns must be a non-empty array")
    forms = doc.get("referenceForms")
    if not isinstance(forms, list):
        raise _fail("referenceForms must be an array")

    seen: set[str] = set()
    patterns: list[PatternDefinition] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise _fail(f"patterns[{index}] must be an object")
        pid = entry.get("id")
        if not isinstance(pid, str) or _ID.fullmatch(pid) is None:
            raise _fail(f"patterns[{index}].id must be a lowercase kebab-case string")
        if pid in seen:
            raise _fail(f"pattern id {pid} is duplicated")
        seen.add(pid)

        ptype = entry.get("type")
        if ptype not in PATTERN_TYPES:
            raise _fail(f"pattern {pid}: type {ptype} is not one of {', '.join(PATTERN_TYPES)}")
        flags = entry.get("flags")
        if flags not in ("", "i"):
            raise _fail(f'pattern {pid}: flags must be "" or "i"')
        confidence = entry.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not (0 < confidence <= 1)
        ):
            raise _fail(f"pattern {pid}: confidence must be a number in (0, 1]")

        validate: Validator | None = None
        name = entry.get("validator")
        if name is not None:
            if not isinstance(name, str) or name not in VALIDATORS:
                raise _fail(f"pattern {pid}: validator {name} is not implemented by this runtime")
            validate = VALIDATORS[name]

        re_flags = re.ASCII | (re.IGNORECASE if flags == "i" else 0)
        patterns.append(
            PatternDefinition(
                id=pid,
                type=cast(PatternType, ptype),
                regex=_compile(f"pattern {pid}", entry.get("regex"), re_flags),
                confidence=float(confidence),
                validate=validate,
            )
        )

    reference_forms: list[re.Pattern[str]] = []
    for index, entry in enumerate(forms):
        if not isinstance(entry, dict):
            raise _fail(f"referenceForms[{index}] must be an object")
        source = entry.get("regex")
        if not isinstance(source, str) or not source.startswith("^") or not source.endswith("$"):
            raise _fail(f"referenceForms[{index}]: regex must be anchored with ^ and $")
        reference_forms.append(_compile(f"referenceForms[{index}]", source, re.ASCII))

    return CompiledPack(
        version=version,
        sha256=hashlib.sha256(data).hexdigest(),
        patterns=patterns,
        reference_forms=reference_forms,
    )


def _read_pack_bytes() -> bytes:
    return (files("aicomply") / "pack" / "patterns.json").read_bytes()


PACK: CompiledPack = compile_pack(_read_pack_bytes())

#: Version of the pattern pack this install loaded.
PACK_VERSION: str = PACK.version

#: SHA-256 (hex) of the pattern pack bytes this install loaded.
PACK_SHA256: str = PACK.sha256


def pack_identity() -> PackIdentity:
    """A fresh ``PackIdentity`` for one result, so no two results share an object."""
    return PackIdentity(version=PACK_VERSION, sha256=PACK_SHA256)
