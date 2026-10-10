"""Pattern pack conformance: per-case exact equality across runtimes.

Port of conformance.ts. Each case in ``pack/conformance/*.jsonl`` carries an
input text and the exact regex-layer outcome every runtime must produce: the
verdict and every violation's type, masked value, offsets, confidence and view.
Aggregate precision and recall can stay inside tolerance while individual
inputs diverge between runtimes; this suite fails on the first divergent case.

The outcome is the deterministic layer only (normalization plus the regex scan
over every content view). The semantic Guard is never consulted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .classifier.dual_layer import _scan_all_views
from .classifier.regex.pack import PACK_SHA256, PACK_VERSION
from .normalize import normalize


def conformance_outcome(text: str) -> dict[str, Any]:
    """The deterministic outcome for one input, in the shape cases are stored in."""
    result = _scan_all_views(normalize(text))
    return {
        "verdict": result.verdict,
        "violations": [
            {
                "type": v.type,
                "value": v.value,
                "start": v.start,
                "end": v.end,
                "confidence": v.confidence,
                "view": v.view,
                "originalStart": v.original_start,
                "originalEnd": v.original_end,
            }
            for v in result.violations
        ],
    }


def load_conformance_cases(directory: Path) -> list[dict[str, Any]]:
    """Read every ``*.jsonl`` case file in ``directory``, in file-name order."""
    cases: list[dict[str, Any]] = []
    ids: set[str] = set()
    for path in sorted(directory.glob("*.jsonl"), key=lambda p: p.name):
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
            if not line.strip():
                continue
            case = json.loads(line)
            if (
                not isinstance(case.get("id"), str)
                or not isinstance(case.get("text"), str)
                or "expected" not in case
            ):
                raise ValueError(f"{path.name}:{number}: a case needs id, text and expected")
            if case["id"] in ids:
                raise ValueError(f"{path.name}:{number}: duplicate case id {case['id']}")
            ids.add(case["id"])
            cases.append(case)
    return cases


def _same_outcome(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    # Compare the contract fields only, so extra keys a future schema adds to a
    # stored case cannot fail an older runtime. ``==`` on the JSON numbers is
    # exact: both runtimes read and write the same IEEE-754 doubles.
    keys = ("type", "value", "start", "end", "confidence", "view", "originalStart", "originalEnd")
    if expected["verdict"] != actual["verdict"]:
        return False
    if len(expected["violations"]) != len(actual["violations"]):
        return False
    missing = object()
    return all(
        all(e.get(k, missing) == a.get(k) for k in keys)
        for e, a in zip(expected["violations"], actual["violations"])
    )


def run_conformance(directory: Path) -> dict[str, Any]:
    """Run every case in ``directory`` against this runtime and build its record."""
    cases = load_conformance_cases(directory)
    failures = []
    for case in cases:
        actual = conformance_outcome(case["text"])
        if not _same_outcome(case["expected"], actual):
            failures.append({"id": case["id"], "expected": case["expected"], "actual": actual})
    return {
        "runtime": "python",
        "packVersion": PACK_VERSION,
        "packSha256": PACK_SHA256,
        "cases": len(cases),
        "passed": len(cases) - len(failures),
        "failures": failures,
    }
