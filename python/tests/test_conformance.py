"""Per-case conformance: the Python port reproduces every stored outcome exactly.

The aggregate parity gate (test_parity.py) passes while individual inputs
diverge between runtimes; an env-var reference returned CREDENTIAL here and no
finding in TypeScript, and the corpus held no such input. This suite compares
every case's verdict and violations field by field.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aicomply.classifier.regex.pack import PACK_SHA256, PACK_VERSION
from aicomply.conformance import conformance_outcome, load_conformance_cases, run_conformance

_REPO_ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = _REPO_ROOT / "pack" / "conformance"

_RECORD = run_conformance(CASES_DIR)


def test_passes_every_case_against_the_loaded_pack():
    assert [f["id"] for f in _RECORD["failures"]] == []
    assert _RECORD["passed"] == _RECORD["cases"]


def test_records_the_pack_it_ran_against():
    assert _RECORD["runtime"] == "python"
    assert _RECORD["packVersion"] == PACK_VERSION
    assert _RECORD["packSha256"] == PACK_SHA256


def test_covers_the_full_corpus_plus_the_regression_cases():
    ids = [c["id"] for c in load_conformance_cases(CASES_DIR)]
    assert len(ids) == _RECORD["cases"]
    corpus = [i for i in ids if not i.startswith(("regression-", "mrn-containsdigit-"))]
    assert len(corpus) == 3200
    for required in (
        "regression-19-process-env",
        "regression-19-bearer-reference",
        "regression-19-control-literal-beside-reference",
        "regression-20-empty-key-next-line",
        "regression-20-env-example-template",
        "regression-20-control-next-line-value",
    ):
        assert required in ids


@pytest.mark.parametrize(
    "text",
    [
        "const apiKey = process.env.OPENAI_API_KEY;",
        "Authorization: Bearer process.env.GITHUB_ACCESS_TOKEN",
        "OPENAI_API_KEY=\nBAR=your-key-here\n",
    ],
)
def test_env_reference_and_empty_assignment_report_nothing(text):
    # The divergence this suite was built to catch, stated directly.
    assert conformance_outcome(text) == {"verdict": "CLEAN", "violations": []}


def test_fails_a_case_whose_stored_outcome_differs(tmp_path):
    # The suite is not vacuous: one wrong field in one case turns it red.
    text = "const apiKey = process.env.OPENAI_API_KEY;"
    good = {"id": "good", "text": text, "expected": conformance_outcome(text)}
    bad = {
        "id": "bad",
        "text": "SSN 123-45-6789",
        "expected": {"verdict": "VIOLATION", "violations": []},
    }
    (tmp_path / "cases.jsonl").write_text(json.dumps(good) + "\n" + json.dumps(bad) + "\n")
    result = run_conformance(tmp_path)
    assert result["cases"] == 2
    assert result["passed"] == 1
    assert [f["id"] for f in result["failures"]] == ["bad"]


def test_refuses_a_duplicate_case_id(tmp_path):
    case = {"id": "same", "text": "x", "expected": {"verdict": "CLEAN", "violations": []}}
    (tmp_path / "a.jsonl").write_text(json.dumps(case) + "\n" + json.dumps(case) + "\n")
    with pytest.raises(ValueError, match="duplicate case id same"):
        load_conformance_cases(tmp_path)
