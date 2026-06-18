"""Normalization layer tests (mirror normalize/__tests__/normalize.test.ts)."""

from __future__ import annotations

import base64
from urllib.parse import quote

from aicomply.normalize import normalize
from aicomply.normalize.encoded import extract_encoded
from aicomply.normalize.nfkc import normalize_nfkc
from aicomply.normalize.whitespace import build_compact_form
from aicomply.normalize.zero_width import strip_zero_width


def test_nfkc_folds_fullwidth_digits():
    r = normalize_nfkc("２０６")  # fullwidth 2 0 6
    assert r.output == "206"
    assert r.changed_count == 3
    assert len(r.offset_map) == len(r.output)


def test_nfkc_preserves_distinct_cyrillic():
    # Cyrillic 'а' (U+0430) is NOT folded by NFKC.
    r = normalize_nfkc("аbc")
    assert r.output == "аbc"
    assert r.changed_count == 0


def test_strip_zero_width():
    r = strip_zero_width("7​9​6")
    assert r.output == "796"
    assert r.removed_count == 2


def test_compact_form_strips_intra_token_whitespace_only():
    r = build_compact_form("1 0 9-8 9-7 2 6 2")
    assert r.compact == "109-89-7262"
    # prose whitespace between words must be preserved (both neighbors non-token)
    r2 = build_compact_form("My SSN here")
    assert r2.compact == "My SSN here"
    assert r2.removed_count == 0


def test_normalize_records_steps():
    res = normalize("２０６-０１-３７５９")
    transforms = {s.transform for s in res.steps}
    assert "nfkc" in transforms
    assert res.normalized_content == "206-01-3759"


def test_extract_base64_payload():
    inner = "Record holds value=899-80-8983 verified"
    blob = base64.b64encode(inner.encode()).decode()
    exts = extract_encoded(f"payload: {blob}")
    assert any(e.source == "decoded-base64" and "899-80-8983" in e.decoded for e in exts)


def test_extract_url_encoded_payload():
    raw = "record = 082-34-7249; type = sensitive"
    encoded = quote(raw)
    exts = extract_encoded(f"data: {encoded}")
    assert any(e.source == "decoded-url" and "082-34-7249" in e.decoded for e in exts)


def test_base64_rejects_non_roundtrip_garbage():
    # Random prose-shaped base64 that is not valid utf-8 round-trips is rejected.
    exts = extract_encoded("short")  # below MIN_CANDIDATE_LENGTH
    assert exts == []


def test_normalize_full_pipeline_through_comply_views():
    # End-to-end: an SSN hidden behind zero-width chars is caught on normalized view.
    res = normalize("SSN 5​1​6-​8​1-​3​0​8​6")
    assert "516-81-3086" in res.normalized_content
