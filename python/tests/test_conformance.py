"""Per-case conformance: the Python port reproduces every stored outcome exactly.

The aggregate parity gate (test_parity.py) passes while individual inputs
diverge between runtimes; an env-var reference returned CREDENTIAL here and no
finding in TypeScript, and the corpus held no such input. This suite compares
every case's verdict and violations field by field.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import aicomply
from aicomply.classifier.regex.pack import PACK_SHA256, PACK_VERSION
from aicomply.conformance import conformance_outcome, load_conformance_cases, run_conformance

_REPO_ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = _REPO_ROOT / "pack" / "conformance"

_RECORD = run_conformance(CASES_DIR)

_CORPUS_ORIGIN = re.compile(r"^bench/corpus/([^/:]+)\.jsonl:(\d+)$")


def _is_seeded(case: dict) -> bool:
    """Whether ``case`` claims a corpus origin. The seed script writes every
    origin as a string, so a missing, null or other non-string origin marks a
    case that was not seeded from the corpus."""
    origin = case.get("origin")
    return isinstance(origin, str) and origin.startswith("bench/corpus/")


def _seeded(cases: list[dict]) -> list[dict]:
    return [c for c in cases if _is_seeded(c)]


def _seed_drift(root: Path) -> list[str]:
    """Every corpus-seeded case under ``root`` that no longer matches what
    ``scripts/conformance.mjs --seed`` would write for it: a file not named
    ``<class>-cases.jsonl`` after its corpus file, or text that differs from the
    corpus record its ``origin`` names. Line numbers count non-empty lines, as
    the seed script does."""
    corpus: dict[str, list[str]] = {}
    drift: list[str] = []
    for path in sorted((root / "pack" / "conformance").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").split("\n"):
            if line.strip() == "":
                continue
            case = json.loads(line)
            if not _is_seeded(case):
                continue
            origin = case["origin"]
            match = _CORPUS_ORIGIN.match(origin)
            if match is None:
                drift.append(f"{case['id']}: origin {origin} does not name a corpus line")
                continue
            klass, line_number = match.group(1), int(match.group(2))
            if path.name != f"{klass}-cases.jsonl":
                drift.append(f"{case['id']}: in {path.name}, not {klass}-cases.jsonl")
            if klass not in corpus:
                text = (root / "bench" / "corpus" / f"{klass}.jsonl").read_text(encoding="utf-8")
                corpus[klass] = [rec for rec in text.split("\n") if rec != ""]
            records = corpus[klass]
            in_range = 1 <= line_number <= len(records)
            if not in_range or json.loads(records[line_number - 1]).get("text") != case["text"]:
                drift.append(f"{case['id']}: text differs from {origin}")
    return drift


_STORE_NAME = re.compile(r"^\.?(credentials?|secrets?|passwords?)(\.[a-z0-9]+)*$", re.IGNORECASE)


def _store_named_case_files(cases_dir: Path) -> list[str]:
    """Every ``*.jsonl`` case file in ``cases_dir`` named like a credential
    store: a leaf of ``credential``, ``secret`` or ``password`` plus
    extensions, which secret-file name rules refuse on sight whatever the file
    holds. Checked over every case file, not only the corpus-seeded ones
    ``_seed_drift`` reads."""
    return sorted(p.name for p in cases_dir.glob("*.jsonl") if _STORE_NAME.match(p.name))


def test_passes_every_case_against_the_loaded_pack():
    assert [f["id"] for f in _RECORD["failures"]] == []
    assert _RECORD["passed"] == _RECORD["cases"]


def test_records_the_pack_it_ran_against():
    assert _RECORD["runtime"] == "python"
    assert _RECORD["runtimeVersion"] == aicomply.__version__
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


def test_marks_every_corpus_seeded_case_as_fake_fixture_text():
    # The seeded text carries token-shaped strings; the marker on the same
    # line is what lets a credential scan over the file pass them.
    seeded = _seeded(load_conformance_cases(CASES_DIR))
    assert len(seeded) == 3200
    assert [c["id"] for c in seeded if "FAKE" not in c.get("fixture", "")] == []


def test_holds_each_corpus_class_in_its_cases_file_with_the_corpus_text():
    # The suffix keeps every class clear of secret-file name rules (a bare
    # `credential.jsonl` or `secrets.jsonl` is refused on sight). The text
    # check fails a corpus regeneration that was not followed by a re-seed,
    # which would otherwise keep passing on the old text.
    assert _seed_drift(_REPO_ROOT) == []
    case_files = {p.name for p in CASES_DIR.glob("*.jsonl")}
    corpus_classes = sorted(p.stem for p in (_REPO_ROOT / "bench" / "corpus").glob("*.jsonl"))
    assert [k for k in corpus_classes if f"{k}-cases.jsonl" not in case_files] == []


def test_names_no_case_file_like_a_credential_store():
    assert (CASES_DIR / "credential-cases.jsonl").is_file()
    assert _store_named_case_files(CASES_DIR) == []


def test_reports_a_store_named_case_file_whose_cases_are_not_corpus_seeded(tmp_path):
    # _seed_drift skips cases without a bench/corpus origin, so a regression
    # case moved into `secrets.jsonl` passes it; the name check still fails.
    cases_dir = tmp_path / "pack" / "conformance"
    cases_dir.mkdir(parents=True)
    expected = {"verdict": "CLEAN", "violations": []}
    names = ("secrets.jsonl", ".Passwords.jsonl", "credential-cases.jsonl", "regressions.jsonl")
    for i, name in enumerate(names):
        case = {
            "id": f"regression-{i}",
            "origin": "pull request #19",
            "text": "x",
            "expected": expected,
        }
        (cases_dir / name).write_text(json.dumps(case) + "\n", encoding="utf-8")
    assert _seed_drift(tmp_path) == []
    assert _store_named_case_files(cases_dir) == [".Passwords.jsonl", "secrets.jsonl"]


def test_reports_a_seeded_case_filed_under_its_corpus_name_or_holding_stale_text(tmp_path):
    (tmp_path / "bench" / "corpus").mkdir(parents=True)
    (tmp_path / "pack" / "conformance").mkdir(parents=True)
    (tmp_path / "bench" / "corpus" / "secrets.jsonl").write_text(
        '{"text":"regenerated"}\n{"text":"kept"}\n', encoding="utf-8"
    )
    expected = {"verdict": "CLEAN", "violations": []}
    origin = "bench/corpus/secrets.jsonl"
    stale = {"id": "secrets-0001", "origin": f"{origin}:1", "text": "old", "expected": expected}
    kept = {"id": "secrets-0002", "origin": f"{origin}:2", "text": "kept", "expected": expected}
    (tmp_path / "pack" / "conformance" / "secrets.jsonl").write_text(
        json.dumps(stale) + "\n" + json.dumps(kept) + "\n", encoding="utf-8"
    )
    assert _seed_drift(tmp_path) == [
        "secrets-0001: in secrets.jsonl, not secrets-cases.jsonl",
        "secrets-0001: text differs from bench/corpus/secrets.jsonl:1",
        "secrets-0002: in secrets.jsonl, not secrets-cases.jsonl",
    ]


@pytest.mark.parametrize("origin", [None, 7])
def test_skips_a_case_whose_origin_is_not_a_string(tmp_path, origin):
    # The case is not corpus-seeded (the seed script writes every origin as a
    # string), so the drift check passes over it as the TypeScript twin does.
    (tmp_path / "pack" / "conformance").mkdir(parents=True)
    case = {
        "id": "x",
        "origin": origin,
        "text": "t",
        "expected": {"verdict": "CLEAN", "violations": []},
    }
    (tmp_path / "pack" / "conformance" / "x-cases.jsonl").write_text(
        json.dumps(case) + "\n", encoding="utf-8"
    )
    assert _seed_drift(tmp_path) == []
    assert _seeded([case]) == []


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


@pytest.mark.parametrize("origin", [None, 7, ["bench/corpus/ssn.jsonl:1"]])
def test_refuses_a_case_whose_origin_is_not_a_string(tmp_path, origin):
    # The drift check passes over such a case, so the loader is where it is reported.
    expected = {"verdict": "CLEAN", "violations": []}
    case = {"id": "x", "origin": origin, "text": "t", "expected": expected}
    (tmp_path / "a.jsonl").write_text("\n" + json.dumps(case) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="a.jsonl:2: origin must be a string"):
        load_conformance_cases(tmp_path)
