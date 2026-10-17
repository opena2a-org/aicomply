"""aicomply CLI -- a zero-integration try-path for the dual-layer classifier.

Port of the TS ``src/cli.ts``. The library API (``comply()``) is the production
surface; this CLI exists so a developer can evaluate aicomply against real content
in one command before writing integration code:

    python -m aicomply scan ./support-ticket.txt
    echo "My SSN is 123-45-6789" | aicomply scan
    aicomply scan src/*.log --json

Exit codes make it usable as a CI gate:
    0  CLEAN          - no findings
    1  VIOLATION/DENY - findings present
    2  usage error

Dependency-free by design (argv parsed by hand) to honor the org small-library
pattern and keep parity with the npm CLI's behaviour.
"""

from __future__ import annotations

import json
import sys
from bisect import bisect_left
from dataclasses import dataclass

from . import __version__, comply
from .classifier.guard_client import DEFAULT_NANOMIND_DAEMON_URL
from .classifier.regex.pack import PATTERN_TYPES
from .types import ComplyResult, Violation


class _UsageError(Exception):
    """A recoverable usage error (exit code 2)."""


@dataclass
class _ParsedArgs:
    command: str | None = None
    files: list[str] | None = None
    json: bool = False
    quiet: bool = False
    help: bool = False
    version: bool = False


def _parse_args(argv: list[str]) -> _ParsedArgs:
    parsed = _ParsedArgs(files=[])
    for arg in argv:
        if arg == "--json":
            parsed.json = True
        elif arg in ("--quiet", "-q"):
            parsed.quiet = True
        elif arg in ("--help", "-h"):
            parsed.help = True
        elif arg in ("--version", "-V"):
            parsed.version = True
        elif arg.startswith("-") and arg != "-":
            raise _UsageError(f"unknown option '{arg}'")
        elif parsed.command is None:
            parsed.command = arg
        else:
            parsed.files.append(arg)  # type: ignore[union-attr]
    return parsed


HELP = """aicomply -- inline content classifier for AI agent I/O

Detects SSNs, card and bank account numbers, passport and medical record
numbers, provider identifiers (NPI), credentials and CUI markings before your
agent ships content to a hosted LLM. Runs a deterministic regex layer always,
plus an optional semantic Guard layer when a local nanomind-daemon is reachable.
Email addresses, phone numbers, postal addresses, dates of birth and names are
not detected (see PATTERN CLASSES).

USAGE
  aicomply scan [file...]      Scan files for sensitive content
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings)
  --quiet, -q   Print only the verdict line
  --version,-V  Print version
  --help, -h    This help

PATTERN CLASSES (regex layer)
  SSN         US Social Security numbers
  PAN         payment card numbers
  IBAN        bank account numbers
  PASSPORT    passport numbers
  MRN         medical record numbers
  NPI         US National Provider Identifiers
  CREDENTIAL  API keys and access tokens
  CUI         Controlled Unclassified Information markings
  Content holding only other data, such as email addresses, phone numbers,
  postal addresses, dates of birth or names, is CLEAN. What is not detected:
  https://github.com/opena2a-org/aicomply/blob/main/docs/detection.md

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q

The library API is the production surface: https://github.com/opena2a-org/aicomply
"""


SCAN_HELP = """aicomply scan -- scan files or piped stdin for sensitive content

Runs the deterministic regex layer over each input, plus the optional semantic
Guard layer when a local nanomind-daemon is reachable. Prints a verdict per
input and an overall verdict.

The regex layer checks SSNs, card and bank account numbers, passport and
medical record numbers, provider identifiers (NPI), credentials and CUI
markings (aicomply --help lists the classes). It does not detect email
addresses, phone numbers, postal addresses, dates of birth or names:
  https://github.com/opena2a-org/aicomply/blob/main/docs/detection.md

USAGE
  aicomply scan [file...]      Scan one or more files
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings, values masked;
                each finding carries its line and column in the input)
  --quiet, -q   Print only the verdict line (CLEAN / VIOLATION / DENY)
  --help, -h    This help

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q
"""


# What the CLI prints in place of a detected value. The library's redacted
# ``value`` can still carry most of a short match (a 7-character passport number
# keeps 6 of its characters), and a finding does not record the matched value's
# length (``start``/``end`` can span a keyword such as "Passport:"), so no share
# of the value is printed.
_MASKED_VALUE = "•••"


def _read_stdin() -> str:
    try:
        return sys.stdin.read()
    except Exception:
        return ""


@dataclass
class _Source:
    label: str
    content: str


def _collect_sources(files: list[str]) -> list[_Source]:
    stdin_requested = len(files) == 0 or "-" in files
    real_files = [f for f in files if f != "-"]
    sources: list[_Source] = []

    for f in real_files:
        try:
            with open(f, encoding="utf-8") as fh:
                sources.append(_Source(label=f, content=fh.read()))
        except OSError:
            raise _UsageError(
                f"cannot read '{f}' (check the path). Try 'aicomply --help'."
            ) from None

    if stdin_requested:
        if sys.stdin.isatty():
            raise _UsageError(
                "no input. Pass a file or pipe content:\n"
                "  aicomply scan ./file.txt\n"
                '  echo "My SSN is 123-45-6789" | aicomply scan'
            )
        sources.append(_Source(label="(stdin)", content=_read_stdin()))

    return sources


def _guard_active(result: ComplyResult) -> bool:
    return "guard" in result.classifier_results


# The renderers locate every finding of one input in turn, so the newline
# offsets of the last content are kept instead of recounted per finding: a
# large log can carry thousands of findings.
_newline_cache: tuple[str, list[int]] | None = None


def _newline_offsets(content: str) -> list[int]:
    global _newline_cache
    if _newline_cache is None or _newline_cache[0] is not content:
        offsets: list[int] = []
        i = content.find("\n")
        while i != -1:
            offsets.append(i)
            i = content.find("\n", i + 1)
        _newline_cache = (content, offsets)
    return _newline_cache[1]


def _locate(content: str, original_start: int | None) -> tuple[int, int] | None:
    """(line, column), 1-based, of a position in the original content.

    ``line`` is one plus the number of ``\\n`` before ``original_start`` and
    ``column`` counts from 1 after the last of them, in the string's own
    indexing (code points). Only ``\\n`` ends a line, so a ``\\r`` stays the
    last character of its line. None when there is no position to locate.
    """
    if original_start is None or original_start < 0 or original_start > len(content):
        return None
    offsets = _newline_offsets(content)
    before = bisect_left(offsets, original_start)
    last_newline = offsets[before - 1] if before else -1
    return before + 1, original_start - last_newline


def _locate_finding(content: str, v: Violation) -> tuple[int, int] | None:
    # Only a pattern match comes from a content view and carries original
    # positions. For a decoded-base64 / decoded-url match those positions are
    # the enclosing encoded token, so that is what the location names.
    return None if v.view is None else _locate(content, v.original_start)


def _render_human(sources: list[_Source], results: list[ComplyResult]) -> None:
    out = sys.stdout
    any_guard = False
    total_findings = 0
    worst = "CLEAN"

    out.write("\n")
    for src, res in zip(sources, results):
        if _guard_active(res):
            any_guard = True
        total_findings += len(res.violations)
        if res.verdict == "DENY":
            worst = "DENY"
        elif res.verdict == "VIOLATION" and worst != "DENY":
            worst = "VIOLATION"

        tag = {
            "CLEAN": "CLEAN     ",
            "DENY": "DENY      ",
            "VIOLATION": "VIOLATION ",
        }[res.verdict]
        out.write(f"  {tag} {src.label}")
        if res.verdict == "CLEAN":
            out.write(
                f"   no finding in the {len(PATTERN_TYPES)} pattern classes"
                " (aicomply --help lists them)\n\n"
            )
            continue
        n = len(res.violations)
        out.write(f"   {n} finding{'' if n == 1 else 's'}\n")
        for v in res.violations:
            view = f"  view {v.view}" if v.view and v.view != "normalized" else ""
            loc = _locate_finding(src.content, v)
            where = f"  line {loc[0]} col {loc[1]}" if loc else ""
            out.write(
                f"    {v.type:<12} {_MASKED_VALUE:<18} confidence {v.confidence:.2f}  "
                f"layer {v.classifier}{view}{where}\n"
            )
        out.write("\n")

    if not any_guard:
        out.write(
            f"  Semantic Guard layer: inactive (preview; no nanomind-daemon on "
            f"{DEFAULT_NANOMIND_DAEMON_URL}).\n"
            "  It targets prompt-injection / exfiltration the regex layer cannot see, but the\n"
            "  current model over-flags benign text - preview only, not for production gating.\n"
            "  The daemon ships on npm (not PyPI); it is a local HTTP server this client calls.\n"
            "  Try it: npm i -g @nanomind/daemon && nanomind-daemon start\n\n"
        )

    if worst == "CLEAN":
        # CLEAN is also the verdict for an input no layer detects, so the line
        # states what was checked and makes no claim about the content.
        out.write("Verdict: CLEAN  ·  no findings from the layers that ran.\n")
    else:
        out.write(
            f"Verdict: {worst}  ·  {total_findings} "
            f"finding{'' if total_findings == 1 else 's'} across {len(sources)} "
            f"input{'' if len(sources) == 1 else 's'}. "
            "Block, redact, or log before this content reaches an LLM.\n"
        )


def _json_finding(content: str, v: Violation) -> dict:
    loc = _locate_finding(content, v)
    return {
        "type": v.type,
        "maskedValue": _MASKED_VALUE,
        "confidence": v.confidence,
        "classifier": v.classifier,
        # Only pattern matches come from a content view; a Guard
        # finding has none and prints null.
        "view": v.view,
        # The value is masked, so its place in the input is what a user
        # searches for; null for a finding with no position there.
        "line": loc[0] if loc else None,
        "column": loc[1] if loc else None,
    }


def _render_json(sources: list[_Source], results: list[ComplyResult]) -> None:
    payload = [
        {
            "source": src.label,
            "verdict": res.verdict,
            "guardActive": _guard_active(res),
            "findings": [_json_finding(src.content, v) for v in res.violations],
        }
        for src, res in zip(sources, results)
    ]
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def run(argv: list[str]) -> int:
    """Pure, testable entry point. Returns the exit code; never calls sys.exit."""
    try:
        return _run_inner(argv)
    except _UsageError as err:
        sys.stderr.write(f"aicomply: {err}\n")
        return 2


def _run_inner(argv: list[str]) -> int:
    args = _parse_args(argv)

    if args.version:
        sys.stdout.write(f"{__version__}\n")
        return 0
    # Scan-scoped help: `aicomply scan --help` documents the scan command and
    # its flags rather than falling through to the generic top-level banner.
    if args.command == "scan" and args.help:
        sys.stdout.write(SCAN_HELP)
        return 0
    if args.help or args.command is None:
        sys.stdout.write(HELP)
        return 2 if (args.command is None and not args.help) else 0
    if args.command != "scan":
        sys.stderr.write(
            f"aicomply: unknown command '{args.command}'. Try 'aicomply --help'.\n"
        )
        return 2

    sources = _collect_sources(args.files or [])
    results = [comply(src.content) for src in sources]

    if args.json:
        _render_json(sources, results)
    elif args.quiet:
        worst = (
            "DENY"
            if any(r.verdict == "DENY" for r in results)
            else "VIOLATION"
            if any(r.verdict == "VIOLATION" for r in results)
            else "CLEAN"
        )
        sys.stdout.write(f"{worst}\n")
    else:
        _render_human(sources, results)

    return 1 if any(r.verdict != "CLEAN" for r in results) else 0


def main() -> None:
    """Console-script entry point (configured in pyproject ``project.scripts``)."""
    try:
        code = run(sys.argv[1:])
    except Exception as err:  # noqa: BLE001 - top-level guard, mirror TS bin wrapper
        sys.stderr.write(f"aicomply: {err}\n")
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()
