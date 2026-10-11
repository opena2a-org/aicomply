"""CLI tests (mirror __tests__/cli.test.ts). run() is pure and returns exit codes."""

from __future__ import annotations

import json

from aicomply.cli import _render_json, _Source, run
from aicomply.types import ClassifierResult, ComplyResult, Violation


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
    _render_json([_Source(label="x.txt", content="c")], [result])
    payload = json.loads(capsys.readouterr().out)
    assert "view" in payload[0]["findings"][0]
    assert payload[0]["findings"][0]["view"] is None


def test_scan_quiet(tmp_path, capsys):
    f = tmp_path / "pii.txt"
    f.write_text("SSN 516-81-3086")
    assert run(["scan", str(f), "--quiet"]) == 1
    assert capsys.readouterr().out.strip() == "VIOLATION"


def test_missing_file_exit_2(capsys):
    assert run(["scan", "/no/such/file.txt"]) == 2
    assert "cannot read" in capsys.readouterr().err


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
