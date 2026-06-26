"""CLI tests (mirror __tests__/cli.test.ts). run() is pure and returns exit codes."""

from __future__ import annotations

import json

from aicomply.cli import _mask_value, run


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


def test_scan_quiet(tmp_path, capsys):
    f = tmp_path / "pii.txt"
    f.write_text("SSN 516-81-3086")
    assert run(["scan", str(f), "--quiet"]) == 1
    assert capsys.readouterr().out.strip() == "VIOLATION"


def test_missing_file_exit_2(capsys):
    assert run(["scan", "/no/such/file.txt"]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_mask_value():
    assert _mask_value("AKIA7IEO7LTOBPA48822").startswith("AKIA")
    assert "7IEO7LTOBPA" not in _mask_value("AKIA7IEO7LTOBPA48822")
    assert _mask_value("ab") == "••"
    assert _mask_value("") == "•"
