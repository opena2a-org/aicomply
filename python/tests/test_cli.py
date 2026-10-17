"""CLI tests (mirror __tests__/cli.test.ts). run() is pure and returns exit codes."""

from __future__ import annotations

import io
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import IO

import pytest

import aicomply
from aicomply.classifier.regex.pack import PATTERN_TYPES
from aicomply.cli import _files_glob, _locate, _render_json, _Source, run
from aicomply.types import ClassifierResult, ComplyResult, Violation


def _pipe_stdin(monkeypatch, data: bytes) -> None:
    """Serve ``data`` as stdin from a pipe, not a terminal."""
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data), encoding="utf-8"))


def test_version(capsys):
    assert run(["--version"]) == 0
    assert capsys.readouterr().out.strip() == __import__("aicomply").__version__


def test_help(capsys):
    assert run(["--help"]) == 0
    out = capsys.readouterr().out
    assert "USAGE" in out
    # Top-level help leads with the generic banner, not the scan synopsis.
    assert out.lstrip().startswith("aicomply --")


def test_scan_help_is_scan_scoped(capsys):
    assert run(["scan", "--help"]) == 0
    out = capsys.readouterr().out
    # Scan help must lead with a scan-scoped synopsis (parity with the TS CLI),
    # not fall through to the generic top-level banner.
    assert out.lstrip().startswith("aicomply scan")
    assert "--json" in out
    assert "--quiet" in out
    assert "stdin" in out.lower()


def test_no_command_prints_help_exit_2(capsys):
    assert run([]) == 2
    assert "USAGE" in capsys.readouterr().out


def test_unknown_command_exit_2(capsys):
    assert run(["frobnicate"]) == 2
    assert "unknown command" in capsys.readouterr().err


def test_unknown_option_exit_2(capsys):
    assert run(["scan", "--bogus"]) == 2
    assert "unknown option" in capsys.readouterr().err


def test_scan_clean_file_exit_0(tmp_path, capsys):
    f = tmp_path / "clean.txt"
    f.write_text("The weather is nice. Order 300843 shipped.")
    assert run(["scan", str(f)]) == 0
    out = capsys.readouterr().out
    assert "CLEAN" in out


# CLEAN states what the layers that ran found. It is also the verdict for an
# input the README lists as not detected, so it must never read as a statement
# that the content is safe.
def test_clean_verdict_states_what_was_checked(tmp_path, capsys):
    f = tmp_path / "clean.txt"
    f.write_text("The weather is nice today.")
    assert run(["scan", str(f)]) == 0
    out = capsys.readouterr().out
    assert out.rstrip().splitlines()[-1] == (
        "Verdict: CLEAN  ·  no findings from the layers that ran."
    )


def test_soft_hyphen_ssn_is_not_called_safe(tmp_path, capsys):
    f = tmp_path / "soft-hyphen.txt"
    f.write_text("SSN 12­3-45-6789\n", encoding="utf-8")
    run(["scan", str(f)])
    verdict_line = capsys.readouterr().out.rstrip().splitlines()[-1]
    assert verdict_line.startswith("Verdict: ")
    assert "safe" not in verdict_line.lower()


# The pattern pack has no class for an email address, a phone number, a postal
# address, a date or a name, so content holding only those is CLEAN. The
# per-input line names what was checked, not "no PII".
def test_clean_input_names_the_pattern_classes_checked(tmp_path, capsys):
    email = "@".join(["jane.doe", "example.com"])
    phone = "(303) 555-0142"
    f = tmp_path / "contact.txt"
    f.write_text(f"Reach me at {email} or {phone}\n")
    assert run(["scan", str(f)]) == 0
    out = capsys.readouterr().out
    line = next((ln for ln in out.splitlines() if str(f) in ln), "")
    assert "CLEAN" in line
    assert "PII" not in line
    assert f" {len(PATTERN_TYPES)} pattern classes " in line
    assert "safe" not in line.lower()


def test_help_names_the_pattern_classes_and_links_what_is_not_detected(capsys):
    for argv in (["--help"], ["scan", "--help"]):
        assert run(argv) == 0
        out = capsys.readouterr().out
        assert "docs/detection.md" in out
        assert "Detects PII," not in out
        assert "(PII, credentials, regulated data)" not in out
    # The per-input CLEAN line says `aicomply --help` lists the classes.
    assert run(["--help"]) == 0
    out = capsys.readouterr().out
    for t in PATTERN_TYPES:
        assert re.search(rf"^  {t} +\S", out, re.MULTILINE), t
    assert re.search(r"e-?mail addresses", out, re.IGNORECASE)
    assert "phone numbers" in out


def test_help_describes_exit_code_0_as_what_was_checked(capsys):
    for argv in (["--help"], ["scan", "--help"]):
        assert run(argv) == 0
        out = capsys.readouterr().out
        assert "  0  CLEAN          no findings from the layers that ran\n" in out
        assert "safe" not in out.lower()


def test_scan_pii_file_exit_1(tmp_path, capsys):
    f = tmp_path / "pii.txt"
    f.write_text("SSN 516-81-3086 and AKIA7IEO7LTOBPA48822")
    assert run(["scan", str(f)]) == 1
    out = capsys.readouterr().out
    assert "VIOLATION" in out
    # never prints the raw secret
    assert "AKIA7IEO7LTOBPA48822" not in out


def test_scan_json_output(tmp_path, capsys):
    f = tmp_path / "pii.txt"
    f.write_text("card 4111111111111111 here")
    assert run(["scan", str(f), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["verdict"] == "VIOLATION"
    assert payload[0]["findings"][0]["type"] == "PAN"
    assert "maskedValue" in payload[0]["findings"][0]
    assert "4111111111111111" not in json.dumps(payload)
    assert payload[0]["findings"][0]["view"] == "normalized"


def test_json_prints_null_view_for_a_finding_without_one(capsys):
    # A Guard finding does not come from a content view; the JSON used to
    # default it to "normalized", claiming a canonicalization that never ran.
    guard = Violation(
        type="tool_misuse", value="***GUARD***", start=0, end=1,
        confidence=1.0, classifier="guard",
    )
    result = ComplyResult(
        verdict="VIOLATION",
        violations=[guard],
        classifier_results={
            "regex": ClassifierResult(classifier="regex", verdict="CLEAN"),
            "guard": ClassifierResult(classifier="guard", verdict="VIOLATION", violations=[guard]),
        },
    )
    _render_json([_Source(label="x.txt", content="c", byte_count=1)], [result])
    payload = json.loads(capsys.readouterr().out)
    assert "view" in payload[0]["findings"][0]
    assert payload[0]["findings"][0]["view"] is None


# The value is masked, so a finding's location is the only thing a user can
# search for in a long log or a staged diff (mirror of the TS CLI tests).
_LINE3 = "ticket: SSN 078-05-1120 on file"
_LOCATED = f"line one\nline two\n{_LINE3}\n"
_COLUMN = _LINE3.index("078-05-1120") + 1


def test_finding_line_ends_with_line_and_column(tmp_path, capsys):
    f = tmp_path / "located.txt"
    f.write_text(_LOCATED)
    assert run(["scan", str(f)]) == 1
    lines = capsys.readouterr().out.split("\n")
    finding = next(line for line in lines if line.startswith("    SSN "))
    assert finding.endswith(f"layer regex  line 3 col {_COLUMN}")


def test_json_finding_carries_line_and_column(tmp_path, capsys):
    f = tmp_path / "located.txt"
    f.write_text(_LOCATED)
    assert run(["scan", str(f), "--json"]) == 1
    finding = json.loads(capsys.readouterr().out)[0]["findings"][0]
    assert finding["type"] == "SSN"
    assert finding["line"] == 3
    assert finding["column"] == _COLUMN
    assert list(finding) == [
        "type", "maskedValue", "confidence", "classifier", "view", "line", "column",
    ]


def test_json_prints_null_location_for_a_finding_without_one(capsys):
    guard = Violation(
        type="tool_misuse", value="***GUARD***", start=0, end=1,
        confidence=1.0, classifier="guard",
    )
    result = ComplyResult(
        verdict="VIOLATION",
        violations=[guard],
        classifier_results={
            "regex": ClassifierResult(classifier="regex", verdict="CLEAN"),
            "guard": ClassifierResult(classifier="guard", verdict="VIOLATION", violations=[guard]),
        },
    )
    _render_json([_Source(label="x.txt", content="line one\nline two\n", byte_count=18)], [result])
    finding = json.loads(capsys.readouterr().out)[0]["findings"][0]
    assert finding["line"] is None
    assert finding["column"] is None


# The column counts code points, as the TS CLI does: a character outside the
# Basic Multilingual Plane is one column (mirror of the TS CLI tests).
_EMOJI = "\U0001F600"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"{_EMOJI}{_EMOJI} SSN 078-05-1120", (1, 8)),
        (f"{_EMOJI}{_EMOJI}\nSSN 078-05-1120", (2, 5)),
        # A lone high surrogate, then an emoji.
        (f"\ud83d{_EMOJI} SSN 078-05-1120", (1, 8)),
    ],
)
def test_locate_counts_the_column_in_code_points(text, expected):
    assert _locate(text, text.index("078-05-1120")) == expected


def test_column_counts_a_character_outside_the_bmp_once(tmp_path, capsys):
    f = tmp_path / "located-emoji.txt"
    f.write_text(f"{_EMOJI}{_EMOJI} SSN 078-05-1120\n", encoding="utf-8")
    assert run(["scan", str(f), "--json"]) == 1
    finding = json.loads(capsys.readouterr().out)[0]["findings"][0]
    assert (finding["type"], finding["line"], finding["column"]) == ("SSN", 1, 8)
    assert run(["scan", str(f)]) == 1
    lines = capsys.readouterr().out.split("\n")
    finding_line = next(line for line in lines if line.startswith("    SSN "))
    assert finding_line.endswith("layer regex  line 1 col 8")


def test_scan_quiet(tmp_path, capsys):
    f = tmp_path / "pii.txt"
    f.write_text("SSN 516-81-3086")
    assert run(["scan", str(f), "--quiet"]) == 1
    assert capsys.readouterr().out.strip() == "VIOLATION"


# comply() runs no layer on empty content and returns CLEAN, so a stdin that was
# never connected, or an empty file, must not pass the gate as CLEAN (mirror of
# the TS CLI tests).
_MODES = ([], ["--json"], ["--quiet"])


def test_stdin_of_0_bytes_exits_2_with_no_input(monkeypatch, capsys):
    for mode in _MODES:
        _pipe_stdin(monkeypatch, b"")
        assert run(["scan", *mode]) == 2, mode
        captured = capsys.readouterr()
        assert captured.out == "", mode
        assert captured.err == "aicomply: no input: (stdin) delivered 0 bytes\n", mode


def test_file_of_0_bytes_exits_2_with_no_input(tmp_path, capsys):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    for mode in _MODES:
        assert run(["scan", str(f), *mode]) == 2, mode
        captured = capsys.readouterr()
        assert captured.out == "", mode
        assert captured.err == f"aicomply: no input: {f} is 0 bytes\n", mode


def test_no_input_names_each_input_of_0_bytes(tmp_path, monkeypatch, capsys):
    a = tmp_path / "empty-a.txt"
    b = tmp_path / "empty-b.txt"
    a.write_bytes(b"")
    b.write_bytes(b"")
    _pipe_stdin(monkeypatch, b"")
    assert run(["scan", str(a), "-", str(b)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"aicomply: no input: {a} is 0 bytes, {b} is 0 bytes, (stdin) delivered 0 bytes\n"
    )


def test_whitespace_only_input_is_scanned_and_json_gives_bytes_and_layers(monkeypatch, capsys):
    _pipe_stdin(monkeypatch, b"\n")
    assert run(["scan", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    [entry] = json.loads(captured.out)
    assert list(entry) == ["source", "bytes", "verdict", "guardActive", "layers", "findings"]
    assert entry == {
        "source": "(stdin)",
        "bytes": 1,
        "verdict": "CLEAN",
        "guardActive": False,
        "layers": ["normalize", "regex"],
        "findings": [],
    }


# Bytes that are not valid UTF-8 become U+FFFD and the rest is scanned, as Node's
# Buffer.toString('utf8') does in the TS CLI: 0xff 0xfe are two replacement
# characters, so the SSN starts at column 18 in both CLIs.
_NOT_UTF8 = b"bad \xff\xfe bytes SSN 078-05-1120\n"


def _assert_not_utf8_entry_is_scanned(entry: dict, source: str) -> None:
    assert entry["source"] == source
    assert entry["bytes"] == len(_NOT_UTF8)
    assert entry["verdict"] == "VIOLATION"
    assert entry["layers"] == ["normalize", "regex"]
    [finding] = entry["findings"]
    assert (finding["type"], finding["line"], finding["column"]) == ("SSN", 1, 18)


def test_stdin_that_is_not_utf8_is_scanned_with_replacement_characters(monkeypatch, capsys):
    _pipe_stdin(monkeypatch, _NOT_UTF8)
    assert run(["scan", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    [entry] = json.loads(captured.out)
    _assert_not_utf8_entry_is_scanned(entry, "(stdin)")

    _pipe_stdin(monkeypatch, _NOT_UTF8)
    assert run(["scan"]) == 1
    out = capsys.readouterr().out
    assert "CLEAN" not in out
    assert "layer regex  line 1 col 18" in out


def test_file_that_is_not_utf8_is_scanned_with_replacement_characters(tmp_path, capsys):
    f = tmp_path / "not-utf8.txt"
    f.write_bytes(_NOT_UTF8)
    assert run(["scan", str(f), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    [entry] = json.loads(captured.out)
    _assert_not_utf8_entry_is_scanned(entry, str(f))


# Text that starts with a UTF-32 or UTF-16 byte order mark is decoded in that
# encoding without the mark. Decoded as UTF-8 it reached the patterns with NUL
# characters between its letters and was reported CLEAN.
_BOM_TEXT = "Customer SSN 078-05-1120 on file\n"
_BOM_INPUTS = {
    "utf-16-le": b"\xff\xfe" + _BOM_TEXT.encode("utf-16-le"),
    "utf-16-be": b"\xfe\xff" + _BOM_TEXT.encode("utf-16-be"),
    "utf-32-le": b"\xff\xfe\x00\x00" + _BOM_TEXT.encode("utf-32-le"),
    "utf-32-be": b"\x00\x00\xfe\xff" + _BOM_TEXT.encode("utf-32-be"),
}


def _assert_bom_entry_is_scanned(entry: dict, source: str, data: bytes) -> None:
    assert entry["source"] == source
    assert entry["bytes"] == len(data)
    assert entry["verdict"] == "VIOLATION"
    [finding] = entry["findings"]
    assert (finding["type"], finding["line"], finding["column"]) == ("SSN", 1, 14)


@pytest.mark.parametrize("encoding", sorted(_BOM_INPUTS))
def test_file_with_a_utf16_or_utf32_byte_order_mark_is_decoded_in_that_encoding(
    encoding, tmp_path, capsys
):
    data = _BOM_INPUTS[encoding]
    f = tmp_path / f"{encoding}.txt"
    f.write_bytes(data)
    assert run(["scan", str(f), "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    [entry] = json.loads(captured.out)
    _assert_bom_entry_is_scanned(entry, str(f), data)

    assert run(["scan", str(f), "--quiet"]) == 1
    assert capsys.readouterr().out == "VIOLATION\n"


@pytest.mark.parametrize("encoding", sorted(_BOM_INPUTS))
def test_stdin_with_a_utf16_or_utf32_byte_order_mark_is_decoded_in_that_encoding(
    encoding, monkeypatch, capsys
):
    data = _BOM_INPUTS[encoding]
    _pipe_stdin(monkeypatch, data)
    assert run(["scan", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    [entry] = json.loads(captured.out)
    _assert_bom_entry_is_scanned(entry, "(stdin)", data)


def test_utf16_and_utf32_units_that_do_not_decode_become_replacement_characters(
    tmp_path, capsys
):
    # UTF-32LE: a surrogate unit, a unit above U+10FFFF and 2 bytes left over;
    # UTF-16BE: a lone high surrogate and 1 byte left over. Each becomes one
    # U+FFFD, so the number after "SSN " starts at column 7 and 6, as in the
    # TS CLI.
    ssn = "SSN 078-05-1120 "
    cases = {
        "utf-32-le": (
            b"\xff\xfe\x00\x00"
            + b"\x00\xd8\x00\x00\xff\xff\x11\x00"
            + ssn.encode("utf-32-le")
            + b"Z\x00",
            7,
        ),
        "utf-16-be": (b"\xfe\xff" + b"\xd8\x00" + ssn.encode("utf-16-be") + b"Z", 6),
    }
    for name, (data, column) in cases.items():
        f = tmp_path / f"bad-{name}.txt"
        f.write_bytes(data)
        assert run(["scan", str(f), "--json"]) == 1
        [entry] = json.loads(capsys.readouterr().out)
        [finding] = entry["findings"]
        assert (name, finding["type"], finding["column"]) == (name, "SSN", column)


def test_input_of_0_bytes_beside_others_is_reported_and_scanned_inputs_decide(tmp_path, capsys):
    empty = tmp_path / "empty.txt"
    clean = tmp_path / "clean.txt"
    dirty = tmp_path / "dirty.txt"
    empty.write_bytes(b"")
    clean.write_bytes(b"nothing here")
    dirty.write_bytes(b"card 4111111111111111")

    assert run(["scan", str(empty), str(clean)]) == 0
    lines = capsys.readouterr().out.rstrip().splitlines()
    assert f"  EMPTY      {empty}   0 bytes, nothing to classify" in lines
    assert lines[-1] == "Verdict: CLEAN  ·  no findings from the layers that ran."

    assert run(["scan", str(empty), str(clean), "--json"]) == 0
    empty_entry, clean_entry = json.loads(capsys.readouterr().out)
    assert (empty_entry["source"], empty_entry["bytes"]) == (str(empty), 0)
    assert (empty_entry["layers"], empty_entry["findings"]) == ([], [])
    assert (clean_entry["bytes"], clean_entry["layers"]) == (12, ["normalize", "regex"])

    assert run(["scan", str(empty), str(dirty), "--quiet"]) == 1
    assert capsys.readouterr().out == "VIOLATION\n"


def test_help_gives_the_exit_code_for_no_input(capsys):
    for argv in (["--help"], ["scan", "--help"]):
        assert run(argv) == 0
        assert (
            "  2  usage error, or no input: stdin is a terminal or every input is 0 bytes\n"
            in capsys.readouterr().out
        )


def test_missing_file_exit_2(capsys):
    assert run(["scan", "/no/such/file.txt"]) == 2
    assert "cannot read" in capsys.readouterr().err


def _sh(script: str) -> str:
    return subprocess.run(
        ["/bin/sh", "-c", script], capture_output=True, text=True, check=True
    ).stdout


# A directory used to get the missing-file message, "check the path", though the
# path exists.
def test_directory_argument_names_the_glob_for_the_files_in_it(tmp_path, capsys):
    d = tmp_path / "adir"
    d.mkdir()
    (d / "clean.txt").write_text("The weather is nice today.")
    # The temporary path holds no character the glob would quote.
    assert re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", str(d))
    for arg in (str(d), f"{d}/"):
        assert run(["scan", arg]) == 2
        assert capsys.readouterr().err == (
            f"aicomply: '{arg}' is a directory, and directories are not scanned."
            f" Name the files in it:\n  aicomply scan {d}/*.txt\n"
        )

    # The printed glob, expanded by a shell, names the file in the directory,
    # and scanning it exits 0.
    files = _sh(f"printf '%s\\n' {_files_glob(str(d))}").splitlines()
    assert files == [str(d / "clean.txt")]
    assert run(["scan", *files]) == 0


# The glob is pasted into a shell, so the shell has to read the directory's name
# back out of it.
def test_directory_glob_is_one_shell_word_that_names_the_directory():
    cases = [
        ("adir", "adir"),
        ("adir//", "adir"),
        ("it's a dir", "it's a dir"),
        ("$HOME and `x`", "$HOME and `x`"),
        ("-dash dir", "./-dash dir"),
    ]
    for name, read in cases:
        # set -f stops the shell expanding the glob, so it prints the word itself.
        word = _sh(f"set -f; printf '%s\\n' {_files_glob(name)}")
        assert (name, word) == (name, f"{read}/*.txt\n")
    assert _files_glob("/") == "/*.txt"


# ``--`` ends the options (POSIX utility syntax guideline 10), so a file whose
# name starts with - can be scanned. It used to be an unknown option.
def test_file_named_after_double_dash_is_scanned(tmp_path, capsys):
    f = tmp_path / "after-dashes.txt"
    f.write_text("The weather is nice today.")
    assert run(["scan", "--", str(f)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert f"CLEAN      {f}" in captured.out


def test_each_argument_after_double_dash_is_a_file(tmp_path, monkeypatch, capsys):
    (tmp_path / "-dash.txt").write_text("The weather is nice today.")
    (tmp_path / "--json").write_text("SSN 078-05-1120")
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "--", "-dash.txt", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    # Human output, so the --json after -- was a file and not the option.
    assert re.search(r"^ {2}CLEAN {6}-dash\.txt ", captured.out, re.M)
    assert re.search(r"^ {2}VIOLATION {2}--json ", captured.out, re.M)


def test_options_before_double_dash_still_apply(tmp_path, monkeypatch, capsys):
    (tmp_path / "-dash.txt").write_text("The weather is nice today.")
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "--json", "--", "-dash.txt"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [(p["source"], p["verdict"]) for p in payload] == [("-dash.txt", "CLEAN")]


def test_second_double_dash_is_a_file_name(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "--", "--"]) == 2
    assert capsys.readouterr().err == (
        "aicomply: cannot read '--' (check the path). Try 'aicomply --help'.\n"
    )


def test_dash_argument_without_double_dash_is_still_an_option(tmp_path, monkeypatch, capsys):
    (tmp_path / "-dash.txt").write_text("The weather is nice today.")
    monkeypatch.chdir(tmp_path)
    assert run(["scan", "-dash.txt"]) == 2
    assert capsys.readouterr().err == "aicomply: unknown option '-dash.txt'\n"


def test_help_documents_double_dash(capsys):
    for argv in (["--help"], ["scan", "--help"]):
        run(argv)
        assert (
            "  --            Ends the options; each later argument is an input, so a file\n"
            "                name can start with - (aicomply scan -- -notes.txt)\n"
        ) in capsys.readouterr().out


# With files named and no ``-`` among them, stdin is not scanned. These tests run
# the CLI in a child process so its stdin is a real pipe, socket or file. The
# child imports the aicomply this test imports and inherits NODE_ENV and
# MOCK_NANOMIND_URL from the conftest fixture, so its Guard request goes to the
# closed port, as the tests' own do.
_NOT_READ = "aicomply: stdin not read because files were named; add - to scan it too\n"
_PACKAGE_PARENT = str(Path(aicomply.__file__).resolve().parents[1])


def _scan(
    args: list[str],
    cwd: Path,
    stdin: int | IO[bytes] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """``aicomply scan *args`` in a child process, given ``stdin`` or ``input_text``."""
    return subprocess.run(
        [sys.executable, "-m", "aicomply", "scan", *args],
        stdin=stdin,
        input=input_text,
        capture_output=True,
        text=True,
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": _PACKAGE_PARENT},
        timeout=60,
        check=False,
    )


def _clean_file(tmp_path: Path) -> str:
    f = tmp_path / "clean.txt"
    f.write_text("The weather is nice today.")
    return str(f)


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]], ids=["human", "json", "quiet"])
def test_files_named_pipe_is_not_read_and_one_stderr_line_says_so(tmp_path, flags):
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, b"SSN 078-05-1120\n")
        # The write end stays open while the CLI runs, so a CLI that read
        # stdin would wait for an end of file that does not come.
        result = _scan([_clean_file(tmp_path), *flags], tmp_path, stdin=read_end)
    finally:
        os.close(read_end)
        os.close(write_end)
    assert result.returncode == 0
    assert result.stderr == _NOT_READ


def test_files_named_socket_keeps_the_exit_code_of_the_files(tmp_path):
    dirty = tmp_path / "dirty.txt"
    dirty.write_text("SSN 078-05-1120\n")
    ours, theirs = socket.socketpair()
    with ours, theirs:
        ours.sendall(b"The weather is nice today.\n")
        result = _scan([str(dirty), "--quiet"], tmp_path, stdin=theirs.fileno())
    assert result.returncode == 1
    assert result.stdout == "VIOLATION\n"
    assert result.stderr == _NOT_READ


# A run whose named files are all 0 bytes ends with no input before any report,
# and the pipe it left unread can hold the content meant for it.
@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]], ids=["human", "json", "quiet"])
def test_files_named_all_0_bytes_pipe_line_follows_no_input(tmp_path, flags):
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, b"SSN 078-05-1120\n")
        result = _scan([str(empty), *flags], tmp_path, stdin=read_end)
    finally:
        os.close(read_end)
        os.close(write_end)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == f"aicomply: no input: {empty} is 0 bytes\n" + _NOT_READ


def test_files_named_all_0_bytes_socket_names_each_file_before_the_line(tmp_path):
    a = tmp_path / "empty-a.txt"
    b = tmp_path / "empty-b.txt"
    a.write_bytes(b"")
    b.write_bytes(b"")
    ours, theirs = socket.socketpair()
    with ours, theirs:
        ours.sendall(b"SSN 078-05-1120\n")
        result = _scan([str(a), str(b), "--quiet"], tmp_path, stdin=theirs.fileno())
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == f"aicomply: no input: {a} is 0 bytes, {b} is 0 bytes\n" + _NOT_READ


@pytest.mark.parametrize("holds", ["/dev/null", "an empty file"])
def test_files_named_all_0_bytes_gives_only_no_input_when_stdin_holds_nothing(tmp_path, holds):
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    with empty.open("rb") as stdin:
        source = subprocess.DEVNULL if holds == "/dev/null" else stdin
        result = _scan([str(empty)], tmp_path, stdin=source)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == f"aicomply: no input: {empty} is 0 bytes\n"


@pytest.mark.parametrize("flags", [[], ["--json"], ["--quiet"]], ids=["human", "json", "quiet"])
def test_files_named_file_with_content_on_stdin_is_a_usage_error(tmp_path, flags):
    redirected = tmp_path / "stdin.txt"
    redirected.write_text("SSN 078-05-1120\n")
    with redirected.open("rb") as stdin:
        result = _scan([_clean_file(tmp_path), *flags], tmp_path, stdin=stdin)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "\n  aicomply scan - <files>\n" in result.stderr


@pytest.mark.parametrize("holds", ["/dev/null", "an empty file"])
def test_files_named_prints_nothing_about_stdin_that_holds_nothing(tmp_path, holds):
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    with empty.open("rb") as stdin:
        source = subprocess.DEVNULL if holds == "/dev/null" else stdin
        result = _scan([_clean_file(tmp_path)], tmp_path, stdin=source)
    assert result.returncode == 0
    assert result.stderr == ""


def test_dash_among_files_reads_stdin_as_before(tmp_path):
    result = _scan(
        ["-", _clean_file(tmp_path), "--quiet"], tmp_path, input_text="SSN 078-05-1120\n"
    )
    assert result.returncode == 1
    assert result.stdout == "VIOLATION\n"
    assert result.stderr == ""


def test_scan_prints_no_characters_of_a_detected_value(tmp_path, capsys):
    # A 7-character passport or record number used to print 6 of its 7
    # characters (A123•••56) and an SSN 5 of its 9 digits (123-•••89).
    f = tmp_path / "short.txt"
    f.write_text("Passport: A123456\nMRN: 1234567\nSSN 123-45-6789\n")
    assert run(["scan", str(f)]) == 1
    out = capsys.readouterr().out
    pad = " " * 16
    assert f"    PASSPORT     •••{pad}confidence" in out
    assert f"    MRN          •••{pad}confidence" in out
    assert f"    SSN          •••{pad}confidence" in out
    for fragment in ("A123", "56 ", "1234", "67 ", "123-", "89 "):
        assert fragment not in out

    assert run(["scan", str(f), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    masked = {x["type"]: x["maskedValue"] for x in payload[0]["findings"]}
    assert masked == {"PASSPORT": "•••", "MRN": "•••", "SSN": "•••"}
