#!/usr/bin/env python3
"""Wall time, CPU time and peak resident set of the Python CLI on a large input.

Writes ``--lines`` lines (77,821 by default, 18,988,324 bytes) that each hold one
SSN and one spaced card number to a temporary file, then runs ``python -m
aicomply scan`` on it once per output format: ``--quiet``, the default report and
``--json``. Each run is its own child process with stdout discarded, so the peak
resident set it reports is that run's alone. Nothing is compared against a
limit; the numbers are for reading next to those of an earlier build.

The peak resident set comes from ``os.wait4``, which Windows does not have;
there the script prints the times only.

Usage:
    python bench/memory.py
    python bench/memory.py --lines 20000
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"

LINE = (
    "Customer SSN 078-05-1120 paid with 4111 1111 1111 1111 and asked for a receipt by"
    " mail; the agent confirmed the order, noted the delivery window and closed the ticket"
    " after the call ended without any further questions from the customer at all.\n"
)

MODES = (["--quiet"], [], ["--json"])


def run_once(path: str, mode: list[str]) -> tuple[int, float, float | None, int | None]:
    """Exit code, wall seconds, CPU seconds and peak resident bytes of one scan."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SRC), env.get("PYTHONPATH")]))
    args = [sys.executable, "-m", "aicomply", "scan", *mode, path]
    start = time.perf_counter()
    proc = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, env=env
    )
    if not hasattr(os, "wait4"):
        code = proc.wait()
        return code, time.perf_counter() - start, None, None
    _, status, usage = os.wait4(proc.pid, 0)
    wall = time.perf_counter() - start
    proc.returncode = os.waitstatus_to_exitcode(status)
    # ru_maxrss is in bytes on macOS and in kibibytes on Linux.
    peak = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return proc.returncode, wall, usage.ru_utime + usage.ru_stime, peak


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--lines", type=int, default=77_821, help="lines in the input file")
    lines = parser.parse_args().lines

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "large.txt")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(LINE * lines)
        size = os.path.getsize(path)
        print(f"input: {lines:,} lines, {size:,} bytes, 2 findings a line")
        for mode in MODES:
            code, wall, cpu, peak = run_once(path, mode)
            name = " ".join(mode) or "(report)"
            cpu_text = "n/a" if cpu is None else f"{cpu:.2f} s"
            peak_text = "n/a" if peak is None else f"{peak / 1e6:,.1f} MB"
            print(
                f"{name:<10} exit {code}  wall {wall:.2f} s  cpu {cpu_text}"
                f"  peak resident set {peak_text}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
