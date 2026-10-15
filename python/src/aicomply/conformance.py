"""Pattern pack conformance: per-case exact equality across runtimes.

Port of conformance.ts. Each case in ``pack/conformance/*.jsonl`` is one JSON
line, ``{"id", "input", "expect": {"types", "verdict", "violations"?}}`` plus
optional ``origin``, ``fixture`` and ``note``. ``expect.types`` (the sorted distinct
violation types) and ``expect.verdict`` are the outcome every runtime must
reproduce exactly; a case that also stores ``expect.violations`` (each
violation's type, masked value, offsets, confidence and view) requires those
to match exactly as well. Aggregate precision and recall can stay inside
tolerance while individual inputs diverge between runtimes; this suite fails
on the first divergent case.

The outcome is the deterministic layer only (normalization plus the regex scan
over every content view). The semantic Guard is never consulted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .classifier.dual_layer import _scan_all_views
from .classifier.regex.pack import PACK_SHA256, PACK_VERSION
from .normalize import normalize


def _sorted_distinct(values: list[str]) -> list[str]:
    # Type names are ASCII, so this order equals every runtime's default string order.
    return sorted(set(values))


def conformance_outcome(text: str) -> dict[str, Any]:
    """The deterministic outcome for one case ``input``, in the shape cases are stored in."""
    result = _scan_all_views(normalize(text))
    violations = [
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
    ]
    return {
        "types": _sorted_distinct([v.type for v in result.violations]),
        "verdict": result.verdict,
        "violations": violations,
    }


def _check_case(where: str, case: Any) -> dict[str, Any]:
    """Check one parsed line against the case contract; ``where`` is ``file:line``."""
    if (
        not isinstance(case, dict)
        or not isinstance(case.get("id"), str)
        or not isinstance(case.get("input"), str)
        or not isinstance(case.get("expect"), dict)
    ):
        raise ValueError(f"{where}: a case needs id, input and expect")
    if "origin" in case and not isinstance(case["origin"], str):
        raise ValueError(f"{where}: origin must be a string")
    expect = case["expect"]
    types = expect.get("types")
    if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
        raise ValueError(f"{where}: expect.types must be an array of strings")
    if types != _sorted_distinct(types):
        raise ValueError(f"{where}: expect.types must be sorted and distinct")
    if not isinstance(expect.get("verdict"), str):
        raise ValueError(f"{where}: expect.verdict must be a string")
    if "violations" in expect:
        violations = expect["violations"]
        if not isinstance(violations, list) or not all(isinstance(v, dict) for v in violations):
            raise ValueError(f"{where}: expect.violations must be an array of objects")
        if types != _sorted_distinct([str(v.get("type")) for v in violations]):
            raise ValueError(f"{where}: expect.types does not match expect.violations")
    return case


def load_conformance_cases(directory: Path) -> list[dict[str, Any]]:
    """Read every ``*.jsonl`` case file in ``directory``, in file-name order."""
    cases: list[dict[str, Any]] = []
    ids: set[str] = set()
    for path in sorted(directory.glob("*.jsonl"), key=lambda p: p.name):
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
            if not line.strip():
                continue
            case = _check_case(f"{path.name}:{number}", json.loads(line))
            if case["id"] in ids:
                raise ValueError(f"{path.name}:{number}: duplicate case id {case['id']}")
            ids.add(case["id"])
            cases.append(case)
    return cases


def _same_outcome(expect: dict[str, Any], actual: dict[str, Any]) -> bool:
    # Compare the contract fields only, so extra keys a future schema adds to a
    # stored case cannot fail an older runtime. ``==`` on the JSON numbers is
    # exact: both runtimes read and write the same IEEE-754 doubles.
    keys = ("type", "value", "start", "end", "confidence", "view", "originalStart", "originalEnd")
    if expect["verdict"] != actual["verdict"] or expect["types"] != actual["types"]:
        return False
    if "violations" not in expect:
        return True
    if len(expect["violations"]) != len(actual["violations"]):
        return False
    missing = object()
    return all(
        all(e.get(k, missing) == a.get(k) for k in keys)
        for e, a in zip(expect["violations"], actual["violations"])
    )


def run_conformance(directory: Path) -> dict[str, Any]:
    """Run every case in ``directory`` against this runtime and build its record."""
    cases = load_conformance_cases(directory)
    failures = []
    for case in cases:
        actual = conformance_outcome(case["input"])
        if not _same_outcome(case["expect"], actual):
            failures.append({"id": case["id"], "expect": case["expect"], "actual": actual})
    return {
        "runtime": "python",
        "runtimeVersion": __version__,
        "packVersion": PACK_VERSION,
        "packSha256": PACK_SHA256,
        "cases": len(cases),
        "passed": len(cases) - len(failures),
        "failures": failures,
    }
