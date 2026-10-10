"""Pattern pack loader: Python half of the shared pack contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import aicomply
from aicomply.classifier.regex.pack import (
    PACK,
    PACK_SHA256,
    PACK_VERSION,
    PackError,
    compile_pack,
    non_portable_construct,
)
from aicomply.classifier.regex.patterns import PATTERNS

_REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT_PACK = _REPO_ROOT / "pack" / "patterns.json"
PACKAGE_PACK = _REPO_ROOT / "python" / "src" / "aicomply" / "pack" / "patterns.json"

_BYTES = ROOT_PACK.read_bytes()
_DOC = json.loads(_BYTES)


def _with_pattern(pid: str, **override) -> bytes:
    doc = json.loads(_BYTES)
    doc["patterns"] = [{**p, **override} if p["id"] == pid else p for p in doc["patterns"]]
    return json.dumps(doc).encode()


def test_package_copy_is_byte_identical_to_the_repository_pack():
    # Both runtimes must read the same pack; `npm run pack:sync` writes the copy.
    assert PACKAGE_PACK.read_bytes() == _BYTES


def test_reports_version_and_sha256_of_the_loaded_bytes():
    assert PACK_VERSION == _DOC["packVersion"]
    assert PACK_SHA256 == hashlib.sha256(_BYTES).hexdigest()
    assert aicomply.PACK_VERSION == PACK_VERSION
    assert aicomply.PACK_SHA256 == PACK_SHA256


def test_compiles_every_entry_in_pack_order():
    assert [p.id for p in PATTERNS] == [p["id"] for p in _DOC["patterns"]]
    assert len(PACK.reference_forms) == len(_DOC["referenceForms"])


def test_every_pack_regex_is_in_the_portable_subset():
    sources = [p["regex"] for p in _DOC["patterns"]] + [f["regex"] for f in _DOC["referenceForms"]]
    assert [s for s in sources if non_portable_construct(s) is not None] == []


@pytest.mark.parametrize(
    "source,construct",
    [
        (r"\bMRN(?=[A-Z0-9]*\d)", "lookahead"),
        (r"a(?!b)", "lookahead"),
        (r"(?<=a)b", "lookbehind"),
        (r"(?<!a)b", "lookbehind"),
        (r"(a)\1", "backreference"),
        (r"(?<key>a)", "named group"),
        (r"(?P<key>a)", "named group"),
        (r"\k<key>", "named backreference"),
        (r"(?i)abc", "inline modifier group"),
        ("abc\\", "trailing backslash"),
    ],
)
def test_non_portable_construct_refuses(source, construct):
    assert non_portable_construct(source) == construct


@pytest.mark.parametrize(
    "source", [r"(?:api[_-]?key|secret)", r"\(\?=literal", r"[(?=]", r"\b(\d{3}-\d{2}-\d{4})\b"]
)
def test_non_portable_construct_accepts(source):
    assert non_portable_construct(source) is None


@pytest.mark.parametrize(
    "data,message",
    [
        (
            _with_pattern("mrn", regex=r"\bMRN[:\s#-]*(?=[A-Z0-9]*\d)([A-Z0-9]{6,12})\b"),
            "lookahead",
        ),
        (_with_pattern("ssn", validator="luhnModN"), "validator luhnModN"),
        (_with_pattern("ssn", validator="__class__"), "validator __class__"),
        (_with_pattern("ssn", type="PHONE"), "type PHONE"),
        (_with_pattern("ssn", flags="m"), "flags"),
        (_with_pattern("ssn", confidence=1.5), "confidence"),
        (_with_pattern("pan", id="ssn"), "duplicated"),
        (_with_pattern("ssn", regex=r"(\d{3}"), "does not compile"),
    ],
)
def test_compile_pack_refuses_a_contract_break(data, message):
    with pytest.raises(PackError, match=message):
        compile_pack(data)


def test_compile_pack_refuses_another_schema_version():
    with pytest.raises(PackError, match="schemaVersion 2"):
        compile_pack(json.dumps({**_DOC, "schemaVersion": 2}).encode())


def test_compile_pack_refuses_an_unanchored_reference_form():
    doc = {**_DOC, "referenceForms": [{"id": "loose", "regex": r"process\.env"}]}
    with pytest.raises(PackError, match="anchored"):
        compile_pack(json.dumps(doc).encode())


def test_compile_pack_refuses_bytes_that_are_not_json():
    with pytest.raises(PackError, match="not valid JSON"):
        compile_pack(b'{"schemaVersion":')
