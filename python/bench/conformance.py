#!/usr/bin/env python3
"""Pattern pack conformance runner for the Python runtime.

Runs every case in the repository's ``pack/conformance/*.jsonl`` against this
package, writes ``conformance/python.json`` at the repository root, and exits
non-zero unless ``passed == cases``. The record carries ``packSha256`` so a
release can refuse to publish when the record was produced against a different
pack than the one the package embeds; that check is ``bench/release_gate.py``.

Usage:
    python bench/conformance.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from a source checkout without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aicomply.conformance import run_conformance  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = _REPO_ROOT / "pack" / "conformance"
RECORD_PATH = _REPO_ROOT / "conformance" / "python.json"


def main() -> int:
    record = run_conformance(CASES_DIR)
    RECORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    RECORD_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    print(f"runtime:    {record['runtime']} {record['runtimeVersion']}")
    print(f"pack:       {record['packVersion']} sha256 {record['packSha256']}")
    print(f"cases:      {record['cases']}")
    print(f"passed:     {record['passed']}")
    for failure in record["failures"][:20]:
        print(f"FAIL {failure['id']}")
        print(f"  expect   {json.dumps(failure['expect'])}")
        print(f"  actual   {json.dumps(failure['actual'])}")
    if len(record["failures"]) > 20:
        print(f"... {len(record['failures']) - 20} more")
    print("record:     conformance/python.json")
    return 0 if record["cases"] > 0 and record["passed"] == record["cases"] else 1


if __name__ == "__main__":
    sys.exit(main())
