#!/usr/bin/env python3
"""Release gate for the Python package.

Exits 0 only when ``conformance/python.json`` was written by the version being
published, against the pattern pack that every built artifact embeds, with
every case passing. The artifacts are the files ``python -m build`` leaves in
``dist/``, the same files an upload sends, so the gate reads the pack and the
version out of each wheel and sdist rather than out of the source tree. A
record written against other pack bytes, by another runtime or version, or
with a failing case says nothing about those artifacts, so the gate refuses it.

Run it after ``python bench/conformance.py`` and ``python -m build``, before
the upload. Every reason is printed, one REFUSED line each, then the fix for
each, every distinct fix once: a stray file in ``dist/`` is resolved by
removing it, not by another conformance run. A record that cannot be read
leaves nothing to compare the artifacts with, so beside it the gate reports
what the artifact directory and each artifact lack on their own. Exit 1 on a
refusal, 2 on a usage error.

Usage:
    python bench/release_gate.py [--record <path>] [--dist <dir>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import zipfile
from email.parser import HeaderParser
from pathlib import Path
from typing import Any, NamedTuple

RUNTIME = "python"
PACKAGE = "aicomply"
_REPO_ROOT = Path(__file__).resolve().parents[2]
RECORD_PATH = _REPO_ROOT / "conformance" / "python.json"
DIST_DIR = _REPO_ROOT / "python" / "dist"

RERUN_FIX = (
    "run `python bench/conformance.py` on the commit being released, resolve every FAIL it "
    "prints, then run this gate again"
)
# For a record and an artifact that disagree, and for anything unforeseen.
BOTH_FIX = (
    "run `python bench/conformance.py` and `python -m build` on the commit being released, "
    "resolve every FAIL the first prints, then run this gate again"
)


class Refusal(NamedTuple):
    """One reason the gate refuses, and what resolves it."""

    reason: str
    fix: str


def _build_fix(dist_dir: Path) -> str:
    return (
        f"run `python -m build` on the commit being released into an empty {dist_dir}, "
        "then run this gate again"
    )


def _stray_fix(dist_dir: Path) -> str:
    return (
        f"remove from {dist_dir} every file that is not a wheel or an sdist (an upload sends "
        "all of them), then run this gate again"
    )


def _show(value: Any) -> str:
    """``value`` as JSON, so a missing or mistyped field reads as what it is."""
    return "missing" if value is None else json.dumps(value)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _version(metadata: bytes) -> str | None:
    return HeaderParser().parsestr(metadata.decode("utf-8"))["Version"]


def _read_wheel(path: Path) -> tuple[str | None, bytes | None]:
    """The version and the embedded pack of a wheel; ``None`` for what it lacks."""
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        metadata = sorted(
            n for n in names if n.endswith(".dist-info/METADATA") and n.count("/") == 1
        )
        pack = f"{PACKAGE}/pack/patterns.json"
        return (
            _version(wheel.read(metadata[0])) if len(metadata) == 1 else None,
            wheel.read(pack) if pack in names else None,
        )


def _read_sdist(path: Path) -> tuple[str | None, bytes | None]:
    """The version and the embedded pack of an sdist; ``None`` for what it lacks."""
    with tarfile.open(path, "r:gz") as sdist:
        names = set(sdist.getnames())
        roots = {n.split("/", 1)[0] for n in names}
        if len(roots) != 1:
            return None, None
        root = roots.pop()

        def read(member: str) -> bytes | None:
            handle = sdist.extractfile(member) if member in names else None
            return handle.read() if handle is not None else None

        info = read(f"{root}/PKG-INFO")
        return (
            _version(info) if info is not None else None,
            read(f"{root}/src/{PACKAGE}/pack/patterns.json"),
        )


def _artifact_refusals(path: Path, record: dict[str, Any] | None) -> list[Refusal]:
    """What ``path`` lacks, and with a ``record``, where the two disagree."""
    name = path.name
    build_fix = _build_fix(path.parent)
    if name.endswith(".whl"):
        reader = _read_wheel
    elif name.endswith(".tar.gz"):
        reader = _read_sdist
    else:
        return [
            Refusal(
                f"{name}: not a wheel or an sdist, so the gate cannot read its pack",
                _stray_fix(path.parent),
            )
        ]
    try:
        version, pack = reader(path)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as err:
        return [Refusal(f"{name}: unreadable ({err})", build_fix)]

    sha256 = hashlib.sha256(pack).hexdigest() if pack is not None else None
    print(f"artifact:   {name} version {_show(version)}, pack sha256 {_show(sha256)}")
    reasons = []
    if version is None:
        reasons.append(Refusal(f"{name}: carries no version metadata", build_fix))
    elif record is not None and record.get("runtimeVersion") != version:
        reasons.append(
            Refusal(
                "runtimeVersion: the record was written by "
                f"{_show(record.get('runtimeVersion'))} (aicomply.__version__), "
                f"{name} is {_show(version)}",
                BOTH_FIX,
            )
        )
    if sha256 is None:
        reasons.append(Refusal(f"{name}: carries no pattern pack", build_fix))
    elif record is not None and record.get("packSha256") != sha256:
        reasons.append(
            Refusal(
                "packSha256: the record was written against pack "
                f"{_show(record.get('packSha256'))}, {name} embeds {_show(sha256)}",
                BOTH_FIX,
            )
        )
    return reasons


def _record_refusals(record_path: Path) -> tuple[dict[str, Any] | None, list[Refusal]]:
    """The record, ``None`` when it cannot be read, and every reason it falls short."""
    try:
        text = record_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [Refusal(f"record: {record_path} does not exist", RERUN_FIX)]
    except (OSError, UnicodeDecodeError) as err:
        # A directory, bytes that are not UTF-8, a file this user may not open.
        fix = f"remove what stands in place of {record_path}, then {RERUN_FIX}"
        return None, [Refusal(f"record: {record_path} cannot be read ({err})", fix)]
    try:
        record = json.loads(text)
    except ValueError:
        record = None
    if not isinstance(record, dict):
        return None, [Refusal(f"record: {record_path} is not a JSON object", RERUN_FIX)]
    cases, passed = record.get("cases"), record.get("passed")
    print(
        f"record:     {_show(record.get('runtime'))} {_show(record.get('runtimeVersion'))}, "
        f"pack sha256 {_show(record.get('packSha256'))}, "
        f"{_show(passed)} of {_show(cases)} cases passed"
    )

    reasons = []
    if record.get("runtime") != RUNTIME:
        reasons.append(
            Refusal(
                f"runtime: the record is for {_show(record.get('runtime'))}, "
                f'this gate publishes "{RUNTIME}"',
                RERUN_FIX,
            )
        )
    if not _is_count(cases) or not _is_count(passed):
        reasons.append(
            Refusal(
                "cases: the record needs integer cases and passed, "
                f"got {_show(cases)} and {_show(passed)}",
                RERUN_FIX,
            )
        )
    elif cases == 0:
        reasons.append(Refusal("cases: the record ran no cases", RERUN_FIX))
    elif passed != cases:
        reasons.append(Refusal(f"passed: {passed} of {cases} cases passed", RERUN_FIX))
    return record, reasons


def refusals(record_path: Path, dist_dir: Path) -> list[Refusal]:
    """Every reason the record cannot stand for the artifacts in ``dist_dir``, each with its fix."""
    record, reasons = _record_refusals(record_path)
    artifacts = sorted(p for p in dist_dir.iterdir() if p.is_file()) if dist_dir.is_dir() else []
    if not artifacts:
        reasons.append(
            Refusal(
                f"artifacts: {dist_dir} holds no built artifact, run `python -m build` first",
                _build_fix(dist_dir),
            )
        )
    for artifact in artifacts:
        reasons.extend(_artifact_refusals(artifact, record))
    return reasons


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--record", type=Path, default=RECORD_PATH, help="conformance record")
    parser.add_argument("--dist", type=Path, default=DIST_DIR, help="directory of built artifacts")
    args = parser.parse_args(argv)

    try:
        reasons = refusals(args.record, args.dist)
    except Exception as err:
        # Anything unforeseen is a refusal too: the gate never passes on an error.
        reasons = [Refusal(f"gate: {err}", BOTH_FIX)]

    if not reasons:
        print("release gate: passed")
        return 0
    # Keep the log in order: what was read first, then why it was refused.
    sys.stdout.flush()
    for refusal in reasons:
        print(f"REFUSED {refusal.reason}", file=sys.stderr)
    print("release gate: refused, do not publish", file=sys.stderr)
    for fix in dict.fromkeys(refusal.fix for refusal in reasons):
        print(f"fix: {fix}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
