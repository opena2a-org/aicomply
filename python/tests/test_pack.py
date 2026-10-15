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
from aicomply.classifier.regex.validators import VALIDATORS

_REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT_PACK = _REPO_ROOT / "pack" / "patterns.json"
PACKAGE_PACK = _REPO_ROOT / "python" / "src" / "aicomply" / "pack" / "patterns.json"

_BYTES = ROOT_PACK.read_bytes()
_DOC = json.loads(_BYTES)

#: The per-pattern fields of the pack contract, in file order. ``note`` is optional prose.
CONTRACT_FIELDS = [
    "id",
    "class",
    "source",
    "flags",
    "validator",
    "context",
    "aiisId",
    "techniqueId",
    "fpEstimate",
]


def _with_entry(pid: str, edit) -> bytes:
    doc = json.loads(_BYTES)
    doc["patterns"] = [edit(dict(p)) if p["id"] == pid else p for p in doc["patterns"]]
    return json.dumps(doc).encode()


def _with_pattern(pid: str, **override) -> bytes:
    return _with_entry(pid, lambda p: {**p, **override})


def _without_key(pid: str, key: str) -> bytes:
    return _with_entry(pid, lambda p: {k: v for k, v in p.items() if k != key})


def _superseded_shape(p: dict) -> dict:
    old = {k: v for k, v in p.items() if k not in ("class", "source", "context")}
    return {
        **old,
        "type": p["class"],
        "regex": p["source"],
        "confidence": p["context"]["confidence"],
    }


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
    sources = [p["source"] for p in _DOC["patterns"]] + [
        f["source"] for f in _DOC["referenceForms"]
    ]
    assert [s for s in sources if non_portable_construct(s) is not None] == []


def test_every_pattern_has_exactly_the_contract_fields():
    for p in _DOC["patterns"]:
        assert [k for k in p if k != "note"] == CONTRACT_FIELDS
    assert list(_DOC) == ["schemaVersion", "packVersion", "referenceForms", "patterns"]
    for f in _DOC["referenceForms"]:
        assert [k for k in f if k != "note"] == ["id", "source"]


def test_names_validators_by_the_contract_names():
    by_id = {p["id"]: p["validator"] for p in _DOC["patterns"]}
    assert by_id["ssn"] == "ssnArea"
    assert by_id["pan"] == "luhn"
    assert by_id["iban"] == "mod97"
    assert by_id["npi"] == "npiLuhn"
    assert by_id["mrn"] == "containsDigit"
    assert by_id["generic-key-assignment"] == "notEmptyAssignmentTarget"
    assert by_id["cui-marking"] == "none"
    assert all(name == "none" or name in VALIDATORS for name in by_id.values())


def test_implements_the_same_validator_names_as_every_other_runtime():
    assert sorted(VALIDATORS) == [
        "containsDigit",
        "luhn",
        "mod97",
        "notEmptyAssignmentTarget",
        "npiLuhn",
        "ssnArea",
    ]


def test_compiles_class_source_and_context_confidence_unchanged():
    entries = {p["id"]: p for p in _DOC["patterns"]}
    for p in PATTERNS:
        entry = entries[p.id]
        assert p.type == entry["class"]
        assert p.regex.pattern == entry["source"]
        assert p.confidence == entry["context"]["confidence"]


def test_mrn_lookahead_is_the_contains_digit_validator():
    mrn = next(p for p in _DOC["patterns"] if p["id"] == "mrn")
    assert mrn["validator"] == "containsDigit"
    assert "(?=" not in mrn["source"]


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
            _with_pattern("mrn", source=r"\bMRN[:\s#-]*(?=[A-Z0-9]*\d)([A-Z0-9]{6,12})\b"),
            "lookahead",
        ),
        (_with_pattern("ssn", validator="luhnModN"), "validator luhnModN"),
        (_with_pattern("ssn", validator="ssn"), "validator ssn "),
        (_with_pattern("ssn", validator="__class__"), "validator __class__"),
        (_without_key("ssn", "validator"), "ssn: validator is required"),
        (_with_pattern("cui-marking", validator=None), "validator must be a name"),
        (_with_pattern("ssn", **{"class": "PHONE"}), "class PHONE"),
        (_with_pattern("ssn", flags="m"), "flags"),
        (_with_pattern("ssn", context={"confidence": 1.5}), r"context\.confidence"),
        (_with_pattern("ssn", context=0.95), "context must be an object"),
        (_without_key("ssn", "aiisId"), "aiisId"),
        (_with_pattern("ssn", techniqueId=""), "techniqueId"),
        (_with_pattern("ssn", fpEstimate=2), "fpEstimate"),
        (_with_pattern("pan", id="ssn"), "duplicated"),
        (_with_pattern("ssn", source=r"(\d{3}"), "does not compile"),
        # A pack written to the earlier field names fails closed.
        (_with_entry("ssn", _superseded_shape), "pattern ssn: class None"),
    ],
)
def test_compile_pack_refuses_a_contract_break(data, message):
    with pytest.raises(PackError, match=message):
        compile_pack(data)


def test_compile_pack_accepts_filled_in_mapping_fields():
    data = _with_pattern("ssn", aiisId="AIIS-0001", techniqueId="T-0001", fpEstimate=0.02)
    assert any(p.id == "ssn" for p in compile_pack(data).patterns)


def test_compile_pack_refuses_another_schema_version():
    with pytest.raises(PackError, match="schemaVersion 2"):
        compile_pack(json.dumps({**_DOC, "schemaVersion": 2}).encode())


def test_compile_pack_refuses_an_unanchored_reference_form():
    doc = {**_DOC, "referenceForms": [{"id": "loose", "source": r"process\.env"}]}
    with pytest.raises(PackError, match="anchored"):
        compile_pack(json.dumps(doc).encode())


def test_compile_pack_refuses_bytes_that_are_not_json():
    with pytest.raises(PackError, match="not valid JSON"):
        compile_pack(b'{"schemaVersion":')
