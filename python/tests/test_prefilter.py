"""The literal prefilter skips a pattern only when it cannot match."""

from __future__ import annotations

import dataclasses
import json
import random
from pathlib import Path

import pytest

from aicomply.classifier.regex import patterns as patterns_module
from aicomply.classifier.regex.patterns import PATTERNS, scan_patterns
from aicomply.classifier.regex.prefilter import required_literals

CORPUS = Path(__file__).resolve().parents[2] / "bench" / "corpus"


@pytest.mark.parametrize(
    ("source", "ignore_case", "expected"),
    [
        (r"\b(AKIA[0-9A-Z]{16})\b", False, ("AKIA",)),
        (r"\bMRN[:\s#-]*([A-Z0-9]{6,12})\b", True, ("mrn",)),
        (r"(?:aws[_-]?)?secret[_-]?access", True, ("secret",)),
        (r"(?:api[_-]?key|secret[_-]?key)\s*[:=]", True, ("api", "secret")),
        (r"\b(\d{3}-\d{2}-\d{4})\b", False, None),
        # a character before a quantifier that allows none is not required
        (r"abcd?", False, ("abc",)),
        (r"abc*", False, ("ab",)),
        (r"(?:abc)?xyz", False, ("xyz",)),
        (r"(?:abc)+xyz", False, ("abc",)),
        # one alternative with no literal leaves nothing required
        (r"abc|\d+", False, None),
        (r"ab", False, ("ab",)),
        (r"a", False, None),
        (r"(?<=x)abc", False, None),
        (r"(abc", False, None),
    ],
)
def test_required_literals(source, ignore_case, expected):
    assert required_literals(source, ignore_case) == expected


def _without_prefilter():
    return [dataclasses.replace(p, required=None) for p in PATTERNS]


def _corpus_texts() -> list[str]:
    texts: list[str] = []
    for path in sorted(CORPUS.glob("*.jsonl")):
        texts += [json.loads(line)["text"] for line in path.read_text().splitlines() if line]
    return texts


def _signature(matches):
    return [(m.type, m.start, m.end, m.value) for m in matches]


def test_prefilter_changes_no_match(monkeypatch):
    rng = random.Random(7)
    words = [
        "AKIA", "akia", "sk-", "ghp_", "Bearer", "mrn", "NPI", "Passport", "SECRET",
        "api_key", "Secret_Access_Key", "FOUO", "cui//", "Travel  Document", "1234567890",
        "078-05-1120", "=", ":", " ", "K", "İ", "x",
    ]
    texts = _corpus_texts()
    texts += ["".join(rng.choice(words) for _ in range(rng.randint(1, 12))) for _ in range(3000)]
    with_filter = [_signature(scan_patterns(t)) for t in texts]
    monkeypatch.setattr(patterns_module, "PATTERNS", _without_prefilter())
    without_filter = [_signature(scan_patterns(t)) for t in texts]
    assert with_filter == without_filter
