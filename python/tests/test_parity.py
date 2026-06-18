"""Cross-language parity gate: the Python port MUST reproduce the TS golden.

This is the binding contract from the adoption/port plan: ``bench/corpus`` +
``bench/baseline.json`` are the shared golden produced by the TS implementation.
The Python ``comply()`` must hit each per-class precision/recall within 2pp.
"""

from __future__ import annotations

import json
from pathlib import Path

from aicomply import comply

_REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIR = _REPO_ROOT / "bench" / "corpus"
BASELINE_PATH = _REPO_ROOT / "bench" / "baseline.json"
TOLERANCE = 0.02


def _load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _measure(records, klass):
    tp = fp = fn = 0
    for rec in records:
        detected = {v.type for v in comply(rec["text"], use_guard=False).violations}
        matched = klass in detected
        if rec["label"] == "positive":
            tp += 1 if matched else 0
            fn += 0 if matched else 1
        elif matched:
            fp += 1
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    return precision, recall


def test_python_port_reproduces_ts_baseline():
    baseline = json.loads(BASELINE_PATH.read_text())
    failures = []
    for f in sorted(CORPUS_DIR.glob("*.jsonl")):
        records = _load_jsonl(f)
        klass = records[0]["class"]
        precision, recall = _measure(records, klass)
        b = baseline[klass]
        if precision < b["precision"] - TOLERANCE:
            failures.append(
                f"{klass}: precision {precision:.3f} < baseline {b['precision']:.3f}"
            )
        if recall < b["recall"] - TOLERANCE:
            failures.append(
                f"{klass}: recall {recall:.3f} < baseline {b['recall']:.3f}"
            )
    assert not failures, "parity regressions vs TS baseline:\n" + "\n".join(failures)
