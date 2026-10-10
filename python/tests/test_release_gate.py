"""Release gate: ``bench/release_gate.py`` is the check a publish runs after the
conformance suite and the build.

It must exit non-zero unless the conformance record was written by the version
being published, against the pack every built artifact embeds, with every case
passing. These tests run the script itself against scratch wheels and sdists
laid out the way the build backend lays them out, so they pin the exit code a
release workflow acts on.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from importlib.resources import files
from pathlib import Path

import pytest

import aicomply
from aicomply.conformance import run_conformance

_REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = _REPO_ROOT / "python" / "bench" / "release_gate.py"
CASES_DIR = _REPO_ROOT / "pack" / "conformance"
PACK_BYTES = (files("aicomply") / "pack" / "patterns.json").read_bytes()
VERSION = aicomply.__version__

# The record exactly as the conformance run writes it for this package.
_RECORD = run_conformance(CASES_DIR)


def _metadata(version: str) -> bytes:
    return f"Metadata-Version: 2.4\nName: aicomply\nVersion: {version}\n".encode()


def _wheel(
    dist: Path, version: str = VERSION, pack: bytes | None = PACK_BYTES, metadata: bool = True
) -> str:
    path = dist / f"aicomply-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as wheel:
        if metadata:
            wheel.writestr(f"aicomply-{version}.dist-info/METADATA", _metadata(version))
        if pack is not None:
            wheel.writestr("aicomply/pack/patterns.json", pack)
    return path.name


def _sdist(
    dist: Path, version: str = VERSION, pack: bytes | None = PACK_BYTES, metadata: bool = True
) -> str:
    path = dist / f"aicomply-{version}.tar.gz"
    members = {f"aicomply-{version}/PKG-INFO": _metadata(version)} if metadata else {}
    if pack is not None:
        members[f"aicomply-{version}/src/aicomply/pack/patterns.json"] = pack
    with tarfile.open(path, "w:gz") as sdist:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            sdist.addfile(info, io.BytesIO(data))
    return path.name


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    directory = tmp_path / "dist"
    directory.mkdir()
    return directory


def _gate(dist: Path, record: object = _RECORD) -> subprocess.CompletedProcess[str]:
    """Run the gate on ``dist`` with ``record`` written beside it (``None`` writes none)."""
    record_path = dist.parent / "python.json"
    if isinstance(record, bytes):
        record_path.write_bytes(record)
    elif record is not None:
        text = record if isinstance(record, str) else json.dumps(record, indent=2) + "\n"
        record_path.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(GATE), "--record", str(record_path), "--dist", str(dist)],
        capture_output=True,
        text=True,
        check=False,
    )


def _refused(run: subprocess.CompletedProcess[str]) -> list[str]:
    return [line for line in run.stderr.splitlines() if line.startswith("REFUSED ")]


def _fixes(run: subprocess.CompletedProcess[str]) -> list[str]:
    return [line for line in run.stderr.splitlines() if line.startswith("fix: ")]


_RERUN = (
    "run `python bench/conformance.py` on the commit being released, resolve every FAIL it "
    "prints, then run this gate again"
)
_RERUN_FIX = f"fix: {_RERUN}"
_BOTH_FIX = (
    "fix: run `python bench/conformance.py` and `python -m build` on the commit being released, "
    "resolve every FAIL the first prints, then run this gate again"
)


def _build_fix(dist: Path) -> str:
    return (
        f"fix: run `python -m build` on the commit being released into an empty {dist}, "
        "then run this gate again"
    )


def _stray_fix(dist: Path) -> str:
    return (
        f"fix: remove from {dist} every file that is not a wheel or an sdist (an upload sends "
        "all of them), then run this gate again"
    )


def test_passes_the_record_the_conformance_run_writes_for_these_artifacts(dist):
    assert _RECORD["cases"] > 0
    assert _RECORD["passed"] == _RECORD["cases"]
    wheel, sdist = _wheel(dist), _sdist(dist)
    run = _gate(dist)
    assert "release gate: passed" in run.stdout
    assert f"artifact:   {wheel} version" in run.stdout
    assert f"artifact:   {sdist} version" in run.stdout
    assert "REFUSED" not in run.stdout + run.stderr
    assert run.returncode == 0


@pytest.mark.parametrize("stale", ["wheel", "sdist"])
def test_refuses_when_one_artifact_embeds_another_pack_than_the_record(dist, stale):
    other = PACK_BYTES + b"\n"
    wheel = _wheel(dist, pack=other if stale == "wheel" else PACK_BYTES)
    sdist = _sdist(dist, pack=other if stale == "sdist" else PACK_BYTES)
    run = _gate(dist)
    assert run.returncode == 1
    refused = [line for line in run.stderr.splitlines() if line.startswith("REFUSED ")]
    assert len(refused) == 1
    assert refused[0].startswith(
        f'REFUSED packSha256: the record was written against pack "{_RECORD["packSha256"]}", '
        f"{wheel if stale == 'wheel' else sdist} embeds "
    )
    assert "release gate: refused, do not publish" in run.stderr
    assert "release gate: passed" not in run.stdout


def test_refuses_when_a_case_failed(dist):
    _wheel(dist)
    _sdist(dist)
    cases = _RECORD["cases"]
    run = _gate(dist, {**_RECORD, "passed": cases - 1})
    assert run.returncode == 1
    assert f"REFUSED passed: {cases - 1} of {cases} cases passed" in run.stderr
    assert "fix: run `python bench/conformance.py`" in run.stderr


def test_refuses_a_record_that_ran_no_cases(dist):
    _wheel(dist)
    run = _gate(dist, {**_RECORD, "cases": 0, "passed": 0})
    assert run.returncode == 1
    assert "REFUSED cases: the record ran no cases" in run.stderr


def test_refuses_the_other_runtimes_record_which_carries_the_same_pack_and_case_count(dist):
    _wheel(dist)
    run = _gate(dist, {**_RECORD, "runtime": "typescript"})
    assert run.returncode == 1
    expected = 'REFUSED runtime: the record is for "typescript", this gate publishes "python"'
    assert expected in run.stderr


def test_refuses_an_artifact_of_another_version_than_the_record(dist):
    wheel = _wheel(dist, version="9.9.9")
    run = _gate(dist)
    assert run.returncode == 1
    assert (
        f'REFUSED runtimeVersion: the record was written by "{VERSION}" (aicomply.__version__), '
        f'{wheel} is "9.9.9"' in run.stderr
    )


def test_refuses_when_there_is_no_record(dist):
    _wheel(dist)
    run = _gate(dist, None)
    assert run.returncode == 1
    assert "REFUSED record: " in run.stderr
    assert "python.json does not exist" in run.stderr


def test_says_why_it_cannot_read_a_record_that_is_not_valid_utf8(dist):
    _wheel(dist)
    run = _gate(dist, b"\xff\xfe\x00bad")
    assert run.returncode == 1
    record_path = dist.parent / "python.json"
    assert _refused(run) == [
        f"REFUSED record: {record_path} cannot be read "
        "('utf-8' codec can't decode byte 0xff in position 0: invalid start byte)"
    ]
    assert _fixes(run) == [f"fix: remove what stands in place of {record_path}, then {_RERUN}"]
    assert "release gate: passed" not in run.stdout


def test_says_a_record_that_is_a_directory_cannot_be_read_not_that_it_does_not_exist(dist):
    _wheel(dist)
    record_path = dist.parent / "python.json"
    record_path.mkdir()
    run = _gate(dist, None)
    assert run.returncode == 1
    refused = _refused(run)
    assert len(refused) == 1
    assert refused[0].startswith(f"REFUSED record: {record_path} cannot be read (")
    assert "Is a directory" in refused[0]
    assert "does not exist" not in run.stderr
    assert _fixes(run) == [f"fix: remove what stands in place of {record_path}, then {_RERUN}"]


@pytest.mark.parametrize(
    "record", [None, "[]", b"\xff\xfe\x00bad"], ids=["no-record", "not-an-object", "not-utf-8"]
)
def test_reports_what_the_artifacts_lack_beside_a_record_it_cannot_read(dist, record):
    # With no record to compare against there is no runtimeVersion or packSha256
    # reason, but an empty or incomplete dist/ is still a reason of its own.
    run = _gate(dist, record)
    assert run.returncode == 1
    refused = [line for line in run.stderr.splitlines() if line.startswith("REFUSED ")]
    assert [line.split(":")[0] for line in refused] == ["REFUSED record", "REFUSED artifacts"]

    wheel = _wheel(dist, pack=None)
    sdist = _sdist(dist, metadata=False)
    run = _gate(dist, record)
    assert run.returncode == 1
    refused = [line for line in run.stderr.splitlines() if line.startswith("REFUSED ")]
    assert refused[0].startswith("REFUSED record: ")
    assert sorted(refused[1:]) == sorted(
        [
            f"REFUSED {wheel}: carries no pattern pack",
            f"REFUSED {sdist}: carries no version metadata",
        ]
    )


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
def test_refuses_an_artifact_that_carries_no_version_metadata(dist, artifact):
    # A record without runtimeVersion would match an artifact without a version
    # if the gate compared the two, so only the missing metadata refuses here.
    name = _wheel(dist, metadata=False) if artifact == "wheel" else _sdist(dist, metadata=False)
    record = {k: v for k, v in _RECORD.items() if k != "runtimeVersion"}
    run = _gate(dist, record)
    assert run.returncode == 1
    refused = [line for line in run.stderr.splitlines() if line.startswith("REFUSED ")]
    assert refused == [f"REFUSED {name}: carries no version metadata"]
    assert f"artifact:   {name} version missing" in run.stdout
    assert "release gate: passed" not in run.stdout


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("{", "python.json is not a JSON object"),
        ("[]", "python.json is not a JSON object"),
        (
            {**_RECORD, "cases": "12", "passed": "12"},
            'REFUSED cases: the record needs integer cases and passed, got "12" and "12"',
        ),
        (
            {k: v for k, v in _RECORD.items() if k != "passed"},
            f"REFUSED cases: the record needs integer cases and passed, got {_RECORD['cases']} "
            "and missing",
        ),
        (
            {**_RECORD, "passed": True, "cases": True},
            "REFUSED cases: the record needs integer cases and passed, got true and true",
        ),
        ({**_RECORD, "passed": 10**9}, f"REFUSED passed: 1000000000 of {_RECORD['cases']} cases"),
        (
            {k: v for k, v in _RECORD.items() if k != "packSha256"},
            "REFUSED packSha256: the record was written against pack missing",
        ),
    ],
    ids=[
        "not-json",
        "json-array",
        "string-counts",
        "no-passed",
        "boolean-counts",
        "more-passed-than-cases",
        "no-pack-hash",
    ],
)
def test_refuses_a_malformed_record(dist, record, message):
    _wheel(dist)
    run = _gate(dist, record)
    assert run.returncode == 1
    assert message in run.stderr
    assert "release gate: passed" not in run.stdout


def test_refuses_when_nothing_was_built(dist):
    run = _gate(dist)
    assert run.returncode == 1
    assert "REFUSED artifacts: " in run.stderr
    assert "holds no built artifact, run `python -m build` first" in run.stderr

    missing = _gate(dist / "absent")
    assert missing.returncode == 1
    assert "holds no built artifact" in missing.stderr


def test_refuses_an_artifact_that_carries_no_pack(dist):
    wheel = _wheel(dist, pack=None)
    sdist = _sdist(dist, pack=None)
    run = _gate(dist)
    assert run.returncode == 1
    assert f"REFUSED {wheel}: carries no pattern pack" in run.stderr
    assert f"REFUSED {sdist}: carries no pattern pack" in run.stderr


def test_refuses_a_file_it_cannot_read_as_a_wheel_or_an_sdist(dist):
    _wheel(dist)
    (dist / f"aicomply-{VERSION}.zip").write_bytes(b"PK")
    (dist / "aicomply-0.0.1-py3-none-any.whl").write_bytes(b"not a zip archive")
    (dist / "aicomply-0.0.1.tar.gz").write_bytes(b"not a tar archive")
    run = _gate(dist)
    assert run.returncode == 1
    assert f"REFUSED aicomply-{VERSION}.zip: not a wheel or an sdist" in run.stderr
    assert "REFUSED aicomply-0.0.1-py3-none-any.whl: unreadable" in run.stderr
    assert "REFUSED aicomply-0.0.1.tar.gz: unreadable" in run.stderr


def test_prints_every_reason_not_only_the_first(dist):
    _wheel(dist)
    record = {
        **_RECORD,
        "runtime": "typescript",
        "runtimeVersion": "0.0.0",
        "packSha256": "f" * 64,
        "passed": 0,
    }
    run = _gate(dist, record)
    assert run.returncode == 1
    refused = [line for line in run.stderr.splitlines() if line.startswith("REFUSED ")]
    assert [line.split(":")[0] for line in refused] == [
        "REFUSED runtime",
        "REFUSED passed",
        "REFUSED runtimeVersion",
        "REFUSED packSha256",
    ]


def test_names_removing_a_stray_file_as_its_fix_not_another_run_or_build(dist):
    _wheel(dist)
    _sdist(dist)
    (dist / "notes.txt").write_text("notes\n", encoding="utf-8")
    run = _gate(dist)
    assert run.returncode == 1
    assert _refused(run) == [
        "REFUSED notes.txt: not a wheel or an sdist, so the gate cannot read its pack"
    ]
    assert _fixes(run) == [_stray_fix(dist)]


def test_names_the_build_as_the_fix_for_an_artifact_that_is_missing_or_incomplete(dist):
    assert _fixes(_gate(dist)) == [_build_fix(dist)]

    _wheel(dist, pack=None)
    _sdist(dist, metadata=False)
    (dist / "aicomply-0.0.1.tar.gz").write_bytes(b"not a tar archive")
    run = _gate(dist)
    assert run.returncode == 1
    assert len(_refused(run)) == 3
    assert _fixes(run) == [_build_fix(dist)]


def test_names_the_conformance_run_as_the_fix_for_a_record_that_falls_short(dist):
    _wheel(dist)
    assert _fixes(_gate(dist, None)) == [_RERUN_FIX]
    assert _fixes(_gate(dist, "[]")) == [_RERUN_FIX]
    assert _fixes(_gate(dist, {**_RECORD, "runtime": "typescript", "passed": 0})) == [_RERUN_FIX]


def test_prints_each_distinct_fix_once_in_the_order_of_what_it_refused(dist):
    # A failed case, an artifact of another version and two stray files: four
    # reasons that three different actions resolve.
    _wheel(dist, version="9.9.9")
    (dist / "more.txt").write_text("more\n", encoding="utf-8")
    (dist / "notes.txt").write_text("notes\n", encoding="utf-8")
    run = _gate(dist, {**_RECORD, "passed": _RECORD["cases"] - 1})
    assert run.returncode == 1
    assert [line.split(":")[0] for line in _refused(run)] == [
        "REFUSED passed",
        "REFUSED runtimeVersion",
        "REFUSED more.txt",
        "REFUSED notes.txt",
    ]
    assert _fixes(run) == [_RERUN_FIX, _BOTH_FIX, _stray_fix(dist)]
    # The fixes close the log, after the verdict.
    assert run.stderr.splitlines()[4] == "release gate: refused, do not publish"


def test_refuses_on_an_error_it_did_not_foresee(dist, monkeypatch, capsys):
    # The catch-all: whatever the checks raise, the gate refuses and never passes.
    spec = importlib.util.spec_from_file_location("release_gate", GATE)
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    def unforeseen(*_args: object) -> list[object]:
        raise RuntimeError("boom")

    monkeypatch.setattr(gate, "refusals", unforeseen)
    _wheel(dist)
    _sdist(dist)
    status = gate.main(["--record", str(dist.parent / "python.json"), "--dist", str(dist)])
    out, err = capsys.readouterr()
    assert status == 1
    assert err.splitlines()[:2] == ["REFUSED gate: boom", "release gate: refused, do not publish"]
    assert "release gate: passed" not in out + err
