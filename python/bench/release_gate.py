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
the upload. Every reason is printed, one REFUSED line each: a record that
cannot be read leaves nothing to compare the artifacts with, so beside it the
gate reports what the artifact directory and each artifact lack on their own.
Exit 1 on a refusal, 2 on a usage error.

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
from typing import Any

RUNTIME = "python"
PACKAGE = "aicomply"
_REPO_ROOT = Path(__file__).resolve().parents[2]
RECORD_PATH = _REPO_ROOT / "conformance" / "python.json"
DIST_DIR = _REPO_ROOT / "python" / "dist"


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


def _artifact_refusals(path: Path, record: dict[str, Any] | None) -> list[str]:
    """What ``path`` lacks, and with a ``record``, where the two disagree."""
    name = path.name
    if name.endswith(".whl"):
        reader = _read_wheel
    elif name.endswith(".tar.gz"):
        reader = _read_sdist
    else:
        return [f"{name}: not a wheel or an sdist, so the gate cannot read its pack"]
    try:
        version, pack = reader(path)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as err:
        return [f"{name}: unreadable ({err})"]

    sha256 = hashlib.sha256(pack).hexdigest() if pack is not None else None
    print(f"artifact:   {name} version {_show(version)}, pack sha256 {_show(sha256)}")
    reasons = []
    if version is None:
        reasons.append(f"{name}: carries no version metadata")
    elif record is not None and record.get("runtimeVersion") != version:
        reasons.append(
            f"runtimeVersion: the record was written by {_show(record.get('runtimeVersion'))} "
            f"(aicomply.__version__), {name} is {_show(version)}"
        )
    if sha256 is None:
        reasons.append(f"{name}: carries no pattern pack")
    elif record is not None and record.get("packSha256") != sha256:
        reasons.append(
            f"packSha256: the record was written against pack {_show(record.get('packSha256'))}, "
            f"{name} embeds {_show(sha256)}"
        )
    return reasons


def _record_refusals(record_path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """The record, ``None`` when it cannot be read, and every reason it falls short."""
    try:
        text = record_path.read_text(encoding="utf-8")
    except OSError:
        return None, [f"record: {record_path} does not exist"]
    try:
        record = json.loads(text)
    except ValueError:
        record = None
    if not isinstance(record, dict):
        return None, [f"record: {record_path} is not a JSON object"]
    cases, passed = record.get("cases"), record.get("passed")
    print(
        f"record:     {_show(record.get('runtime'))} {_show(record.get('runtimeVersion'))}, "
        f"pack sha256 {_show(record.get('packSha256'))}, "
        f"{_show(passed)} of {_show(cases)} cases passed"
    )

    reasons = []
    if record.get("runtime") != RUNTIME:
        reasons.append(
            f"runtime: the record is for {_show(record.get('runtime'))}, "
            f'this gate publishes "{RUNTIME}"'
        )
    if not _is_count(cases) or not _is_count(passed):
        reasons.append(
            "cases: the record needs integer cases and passed, "
            f"got {_show(cases)} and {_show(passed)}"
        )
    elif cases == 0:
        reasons.append("cases: the record ran no cases")
    elif passed != cases:
        reasons.append(f"passed: {passed} of {cases} cases passed")
    return record, reasons


def refusals(record_path: Path, dist_dir: Path) -> list[str]:
    """Every reason the record cannot stand for the artifacts in ``dist_dir``."""
    record, reasons = _record_refusals(record_path)
    artifacts = sorted(p for p in dist_dir.iterdir() if p.is_file()) if dist_dir.is_dir() else []
    if not artifacts:
        reasons.append(
            f"artifacts: {dist_dir} holds no built artifact, run `python -m build` first"
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
        reasons = [f"gate: {err}"]

    if not reasons:
        print("release gate: passed")
        return 0
    # Keep the log in order: what was read first, then why it was refused.
    sys.stdout.flush()
    for reason in reasons:
        print(f"REFUSED {reason}", file=sys.stderr)
    print("release gate: refused, do not publish", file=sys.stderr)
    print(
        "fix: run `python bench/conformance.py` and `python -m build` on the commit being "
        "released, resolve every FAIL the first prints, then run this gate again",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
