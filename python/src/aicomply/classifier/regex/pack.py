"""Pattern pack loader: the single construction site of compiled patterns.

Port of classifier/regex/pack.ts. The detection regexes are data in
``aicomply/pack/patterns.json``, a byte-identical copy of the repository's
``pack/patterns.json`` that every runtime reads. This module checks the file
against the pack contract and compiles it; nothing else in the package holds a
detection pattern literal.

The loader fails closed: a missing, malformed or non-portable pack, or one with
a counted repeat that has no upper bound, raises at import time rather than
leaving the classifier running with no patterns, which would report every input
as CLEAN.

Each pattern entry carries ``id``, ``class`` (the violation type a match
reports), ``source`` (the regex), ``flags``, ``validator`` (a name from
``.validators`` or ``"none"``), ``context`` (``{"confidence": ...}``, the
confidence a match carries), and the nullable mapping fields ``aiisId``,
``techniqueId`` and ``fpEstimate``. The file shape is documented once, in
classifier/regex/pack.ts.

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
from .validators import NO_VALIDATOR, VALIDATORS, Validator

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
    #: The entry's ``class``.
    type: PatternType
    #: The entry's ``source``, compiled with its ``flags``.
    regex: re.Pattern[str]
    #: The entry's ``context.confidence``.
    confidence: float
    #: The entry's ``validator``; None for ``"none"``.
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


#: The largest count a counted repeat in the pack may carry. RE2 refuses a
#: larger one, so a larger count is outside the portable subset as well.
MAX_REPEAT_COUNT = 1000

#: A counted repeat at a given position: ``{n}``, ``{n,}`` or ``{n,m}``.
_COUNTED_REPEAT = re.compile(r"\{([0-9]+)(?:(,)([0-9]*))?\}")

#: ``{,}`` or ``{,m}`` at a given position.
_NO_LOWER_BOUND_FORM = re.compile(r"\{,([0-9]*)\}")


def counted_repeat_problem(source: str) -> str | None:
    """Return why a counted repeat in ``source`` keeps it out of the pack, or None.

    Every counted repeat (``{n}``, ``{n,}`` or ``{n,m}`` outside a character
    class) carries an upper bound, and no count above ``MAX_REPEAT_COUNT``.
    The JavaScript regex engine keeps backtracking state for each character a
    counted repeat matches, so one with no upper bound can make it throw on a
    long enough run of the characters it repeats; both runtimes read one pack,
    so this one refuses such a source too. ``{,m}`` and ``{,}`` are refused as
    well: Python reads them as counted repeats, ``{,}`` with no upper bound,
    where JavaScript and RE2 read them as text. An escaped brace and a brace in
    a character class open no counted repeat.
    """
    in_class = False
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        if c == "\\":
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
        if c == "{":
            form = _NO_LOWER_BOUND_FORM.match(source, i)
            if form is not None:
                unbounded = " with no upper bound" if form.group(1) == "" else ""
                return (
                    f"the brace form {form.group(0)}, which Python reads as a counted repeat"
                    f"{unbounded} and JavaScript and RE2 read as text; write {{0,m}} with m "
                    f"at most {MAX_REPEAT_COUNT} for a repeat, or \\{{ for a brace"
                )
            repeat = _COUNTED_REPEAT.match(source, i)
            if repeat is not None:
                text = repeat.group(0)
                low, comma, high = repeat.group(1, 2, 3)
                if comma is not None and high == "":
                    return (
                        f"the counted repeat {text}, which has no upper bound; "
                        f"write it as {{{low},m}} with m at most {MAX_REPEAT_COUNT}"
                    )
                counts = [int(low)] + ([] if high is None else [int(high)])
                if max(counts) > MAX_REPEAT_COUNT:
                    return (
                        f"the counted repeat {text}, whose count is above {MAX_REPEAT_COUNT}, "
                        "the largest RE2 accepts"
                    )
                i += len(text)
                continue
        i += 1
    return None


def _fail(message: str) -> PackError:
    return PackError(f"aicomply pattern pack: {message}")


def _compile(where: str, source: object, flags: int) -> re.Pattern[str]:
    if not isinstance(source, str) or not source:
        raise _fail(f"{where}: source must be a non-empty string")
    construct = non_portable_construct(source)
    if construct is not None:
        raise _fail(f"{where}: source uses a {construct}, which is outside the portable subset")
    repeat = counted_repeat_problem(source)
    if repeat is not None:
        raise _fail(f"{where}: source has {repeat}")
    try:
        return re.compile(source, flags)
    except re.error as err:
        raise _fail(f"{where}: source does not compile ({err})") from err


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_mapping_fields(pid: str, entry: dict[str, object]) -> None:
    """The mapping fields are present on every entry and null until mapped."""
    for key in ("aiisId", "techniqueId"):
        if key not in entry:
            raise _fail(f"pattern {pid}: {key} is missing (use null when unmapped)")
        value = entry[key]
        if value is not None and (not isinstance(value, str) or not value):
            raise _fail(f"pattern {pid}: {key} must be null or a non-empty string")
    if "fpEstimate" not in entry:
        raise _fail(f"pattern {pid}: fpEstimate is missing (use null when unmeasured)")
    fp = entry["fpEstimate"]
    if fp is not None and (
        isinstance(fp, bool) or not isinstance(fp, (int, float)) or not (0 <= fp <= 1)
    ):
        raise _fail(f"pattern {pid}: fpEstimate must be null or a number in [0, 1]")


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

        klass = entry.get("class")
        if klass not in PATTERN_TYPES:
            raise _fail(f"pattern {pid}: class {klass} is not one of {', '.join(PATTERN_TYPES)}")
        flags = entry.get("flags")
        if flags not in ("", "i"):
            raise _fail(f'pattern {pid}: flags must be "" or "i"')
        context = entry.get("context")
        if not isinstance(context, dict):
            raise _fail(f"pattern {pid}: context must be an object")
        confidence = context.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not (0 < confidence <= 1)
        ):
            raise _fail(f"pattern {pid}: context.confidence must be a number in (0, 1]")

        # The key is required in both runtimes; "none" is how an entry says it
        # has no validator, so a missing key is a malformed entry, not "none".
        if "validator" not in entry:
            raise _fail(
                f"pattern {pid}: validator is required"
                f' (a validator name, or "{NO_VALIDATOR}" for no check)'
            )
        name = entry["validator"]
        if not isinstance(name, str):
            raise _fail(
                f'pattern {pid}: validator must be a name, or "{NO_VALIDATOR}" for no check'
            )
        validate: Validator | None = None
        if name != NO_VALIDATOR:
            if name not in VALIDATORS:
                raise _fail(f"pattern {pid}: validator {name} is not implemented by this runtime")
            validate = VALIDATORS[name]
        _check_mapping_fields(pid, entry)

        re_flags = re.ASCII | (re.IGNORECASE if flags == "i" else 0)
        patterns.append(
            PatternDefinition(
                id=pid,
                type=cast(PatternType, klass),
                regex=_compile(f"pattern {pid}", entry.get("source"), re_flags),
                confidence=float(confidence),
                validate=validate,
            )
        )

    reference_forms: list[re.Pattern[str]] = []
    for index, entry in enumerate(forms):
        if not isinstance(entry, dict):
            raise _fail(f"referenceForms[{index}] must be an object")
        source = entry.get("source")
        if not isinstance(source, str) or not source.startswith("^") or not source.endswith("$"):
            raise _fail(f"referenceForms[{index}]: source must be anchored with ^ and $")
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
