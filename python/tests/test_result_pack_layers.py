"""Every comply() result names the pack it ran and the layers that ran
(mirror __tests__/result-pack-layers.test.ts)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import aicomply.classifier.dual_layer as dual_layer
from aicomply import PACK_SHA256, PACK_VERSION, PackIdentity, comply
from aicomply.classifier.guard_client.nanomind_adapter import NANOMIND_INFER_ENDPOINT
from aicomply.types import ClassifierResult

PACK_BYTES = (Path(__file__).resolve().parents[2] / "pack" / "patterns.json").read_bytes()
FILE_SHA256 = hashlib.sha256(PACK_BYTES).hexdigest()
FILE_VERSION = json.loads(PACK_BYTES)["packVersion"]


def test_pack_names_the_embedded_pack_by_version_and_byte_hash():
    res = comply("SSN 516-81-3086", use_guard=False)
    assert res.pack == PackIdentity(version=PACK_VERSION, sha256=PACK_SHA256)
    assert res.pack == PackIdentity(version=FILE_VERSION, sha256=FILE_SHA256)


def test_pack_is_set_on_clean_and_on_empty_content():
    assert comply("nothing to see here", use_guard=False).pack.sha256 == FILE_SHA256
    assert comply("", use_guard=False).pack.sha256 == FILE_SHA256


def test_pack_is_a_fresh_object_per_result():
    a = comply("first", use_guard=False)
    a.pack.sha256 = "tampered"
    assert comply("second", use_guard=False).pack.sha256 == FILE_SHA256


def test_layers_on_regex_only_path():
    res = comply("SSN 516-81-3086", use_guard=False)
    assert "guard" not in res.classifier_results
    assert res.layers == ["normalize", "regex"]


def test_layers_on_unreachable_daemon_omit_guard(recorded_urls: list[str]):
    # The real adapter runs and its request goes to conftest.py's closed port.
    res = comply("SSN 516-81-3086")
    assert res.layers == ["normalize", "regex"]
    assert recorded_urls == ["http://127.0.0.1:1" + NANOMIND_INFER_ENDPOINT]


def test_layers_add_guard_when_the_daemon_answered(monkeypatch: pytest.MonkeyPatch):
    guard = ClassifierResult(classifier="guard", verdict="CLEAN", violations=[])
    monkeypatch.setattr(dual_layer, "classify_with_nanomind_daemon", lambda *a, **k: guard)
    res = comply("hello world")
    assert res.classifier_results["guard"] is guard
    assert res.layers == ["normalize", "regex", "guard"]


def test_layers_empty_when_there_was_no_content():
    assert comply("", use_guard=False).layers == []


def test_to_dict_carries_pack_and_layers_in_the_wire_shape():
    d = comply("SSN 516-81-3086", use_guard=False).to_dict()
    assert d["pack"] == {"version": FILE_VERSION, "sha256": FILE_SHA256}
    assert d["layers"] == ["normalize", "regex"]
    empty = comply("", use_guard=False).to_dict()
    assert empty["pack"] == {"version": FILE_VERSION, "sha256": FILE_SHA256}
    assert empty["layers"] == []
