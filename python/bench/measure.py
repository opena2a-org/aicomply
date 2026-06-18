#!/usr/bin/env python3
"""Cross-language parity harness for the Python aicomply port.

Runs ``comply()`` against the SHARED synthetic corpus at
``aicomply/bench/corpus/*.jsonl`` and compares per-class precision/recall against
the TS-produced golden ``aicomply/bench/baseline.json``. The corpus and baseline
are the single source of truth for both languages (org Registry-change-propagation
discipline): any pattern/threshold change must keep BOTH languages within
tolerance of this baseline.

Exit non-zero if any class's precision or recall drops more than
REGRESSION_TOLERANCE below the TS baseline.

Usage:
    python bench/measure.py            # measure + compare against baseline
    python bench/measure.py --json     # also print machine-readable metrics
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from a source checkout without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aicomply import comply  # noqa: E402

# The TS corpus + baseline live one level up from python/ in the same repo.
_REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = _REPO_ROOT / "bench" / "corpus"
BASELINE_PATH = _REPO_ROOT / "bench" / "baseline.json"

REGRESSION_TOLERANCE = 0.02  # fail if precision or recall drops > 2pp


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def metrics_from_counts(tp: int, fp: int, fn: int) -> dict:
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    f1 = 0.0 if precision + recall == 0 else (2 * precision * recall) / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def measure_class(klass: str, records: list[dict]) -> dict:
    per_variant: dict[str, dict] = {}
    tp = fp = fn = 0
    for rec in records:
        # use_guard=False: the daemon isn't running here, identical to the TS
        # bench (guard on, daemon absent -> regex-only). Keeps the run fast.
        result = comply(rec["text"], use_guard=False)
        detected = {v.type for v in result.violations}
        matched = klass in detected
        variant = rec.get("variant", "canonical")
        pv = per_variant.setdefault(variant, {"tp": 0, "fp": 0, "fn": 0})
        if rec["label"] == "positive":
            if matched:
                pv["tp"] += 1
                tp += 1
            else:
                pv["fn"] += 1
                fn += 1
        else:
            if matched:
                pv["fp"] += 1
                fp += 1
    return {"aggregate": metrics_from_counts(tp, fp, fn), "by_variant": per_variant}


def main() -> int:
    files = sorted(CORPUS_DIR.glob("*.jsonl"))
    measurements: dict[str, dict] = {}

    for f in files:
        records = load_jsonl(f)
        if not records:
            continue
        klass = records[0].get("class")
        if not klass:
            continue
        m = measure_class(klass, records)
        measurements[klass] = m
        a = m["aggregate"]
        print(
            f"{klass:<12} P={a['precision']:.3f}  R={a['recall']:.3f}  "
            f"F1={a['f1']:.3f}  (tp={a['tp']} fp={a['fp']} fn={a['fn']})"
        )
        for v, c in m["by_variant"].items():
            if c["tp"] + c["fn"] > 0:
                r = c["tp"] / (c["tp"] + c["fn"])
                print(f"  {v:<14} recall={r:.3f} (tp={c['tp']} fn={c['fn']})")
            else:
                print(f"  {v:<14} fp={c['fp']}")

    baseline = json.loads(BASELINE_PATH.read_text())
    failures: list[str] = []
    for klass, m in measurements.items():
        b = baseline.get(klass)
        if not b:
            print(f"\n{klass}: new class, no baseline entry yet")
            continue
        dp = m["aggregate"]["precision"] - b["precision"]
        dr = m["aggregate"]["recall"] - b["recall"]
        if dp < -REGRESSION_TOLERANCE:
            failures.append(
                f"{klass}: precision dropped {-dp * 100:.2f}pp "
                f"({b['precision']:.3f} -> {m['aggregate']['precision']:.3f})"
            )
        if dr < -REGRESSION_TOLERANCE:
            failures.append(
                f"{klass}: recall dropped {-dr * 100:.2f}pp "
                f"({b['recall']:.3f} -> {m['aggregate']['recall']:.3f})"
            )

    if "--json" in sys.argv:
        print(
            "\n"
            + json.dumps(
                {k: m["aggregate"] for k, m in measurements.items()}, indent=2
            )
        )

    if failures:
        print("\nREGRESSIONS vs TS baseline:")
        for f in failures:
            print(f"  {f}")
        return 1
    print("\nno regressions vs TS baseline — Python port reproduces the golden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
