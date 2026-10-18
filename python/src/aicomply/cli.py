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
    2  usage error, or no input (stdin is a terminal or every input is 0 bytes)

Dependency-free by design (argv parsed by hand) to honor the org small-library
pattern and keep parity with the npm CLI's behaviour.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import stat
import sys
from bisect import bisect_left
from dataclasses import dataclass
from typing import Literal

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
    # ``--`` ends the options (POSIX utility syntax guideline 10): each later
    # argument is an operand, so a file whose name starts with - can be named.
    options_ended = False
    for arg in argv:
        if options_ended or not arg.startswith("-") or arg == "-":
            if parsed.command is None:
                parsed.command = arg
            else:
                parsed.files.append(arg)  # type: ignore[union-attr]
        elif arg == "--":
            options_ended = True
        elif arg == "--json":
            parsed.json = True
        elif arg in ("--quiet", "-q"):
            parsed.quiet = True
        elif arg in ("--help", "-h"):
            parsed.help = True
        elif arg in ("--version", "-V"):
            parsed.version = True
        else:
            raise _UsageError(f"unknown option '{arg}'")
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
  --version, -V Print version
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)
                A lone - is still stdin after --; name a file called - as ./-

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
  2  usage error, or no input: stdin is a terminal or every input is 0 bytes

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q

The library API is the production surface: https://github.com/opena2a-org/aicomply
"""


SCAN_HELP = """aicomply scan -- scan files or piped stdin for sensitive content

Runs the deterministic regex layer over each input, plus the optional semantic
Guard layer when a local nanomind-daemon is reachable. Prints a verdict per
input and an overall verdict. An input of 0 bytes is not classified: it is
listed as "0 bytes, nothing to classify" (--json: "bytes": 0, "verdict": null,
"layers": []), and the inputs that were scanned decide the exit code.

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
                each finding carries its line and column in the input, and each
                input its size in bytes and the layers that ran)
  --quiet, -q   Print only the verdict line (CLEAN / VIOLATION / DENY)
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)
                A lone - is still stdin after --; name a file called - as ./-

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error, or no input: stdin is a terminal or every input is 0 bytes

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


def _bom_encoding(data: bytes) -> str | None:
    """``utf-32``, ``utf-16`` or ``utf-8-sig`` when ``data`` starts with that
    encoding's byte order mark, else None. Each codec reads the mark and drops
    it; the first two pick the byte order from it. FF FE 00 00 is checked
    first: it is the UTF-32LE mark. Kept, the UTF-8 mark was column 1 of the
    first line, so each finding on that line was one column right of where an
    editor shows it.
    """
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if data.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return None


def _read_stdin() -> tuple[str, int]:
    """The text on stdin and the number of bytes that delivered it.

    Bytes that start with a UTF-32, UTF-16 or UTF-8 byte order mark are decoded
    in that encoding, without the mark, as in the TS CLI. Other bytes are decoded
    with the encoding of ``sys.stdin``, keeping line
    endings except on Windows, where they are translated as in universal-newlines
    mode. A byte sequence the encoding cannot decode becomes U+FFFD and the rest
    is scanned, as Node's ``Buffer.toString('utf8')`` does in the TS CLI. A read
    error leaves the text empty and the byte count 0.
    """
    try:
        data = sys.stdin.buffer.read()
    except Exception:
        return "", 0
    text = io.TextIOWrapper(
        io.BytesIO(data),
        encoding=_bom_encoding(data) or sys.stdin.encoding,
        errors="replace",
        newline=None if sys.platform == "win32" else "\n",
    ).read()
    return text, len(data)


def _stdin_requested(files: list[str]) -> bool:
    """stdin is scanned when no file is named or ``-`` is among the files."""
    return len(files) == 0 or "-" in files


_STDIN_NOT_READ = "stdin not read because files were named; add - to scan it too"


def _unread_stdin() -> Literal["content", "stream"] | None:
    """What stdin holds when files are named without ``-``, so it is not scanned.

    Decided from fstat alone, never by reading: reading a pipe to its end waits
    until its writer closes it, so a writer that holds it open and never writes
    would hold up the scan.

    ``"content"``  a regular file with bytes (``aicomply scan a.txt < b.txt``)
    ``"stream"``   a pipe or socket: what it carries is known only by reading it
    ``None``       anything else: a terminal or /dev/null (character devices),
                   an empty file, or no descriptor 0
    """
    try:
        st = os.fstat(0)
    except OSError:
        return None
    if stat.S_ISREG(st.st_mode):
        return "content" if st.st_size > 0 else None
    if stat.S_ISFIFO(st.st_mode) or stat.S_ISSOCK(st.st_mode):
        return "stream"
    return None


@dataclass
class _Source:
    label: str
    content: str
    # How many bytes the input delivered. An input of 0 bytes is not classified.
    byte_count: int


def _files_glob(directory: str) -> str:
    """The glob the help uses (``src/*.txt``) for the files in ``directory``.

    Written as one POSIX shell word: trailing slashes dropped, ``./`` put before
    a name that starts with -, and the name quoted by ``shlex.quote``.
    """
    trimmed = directory.rstrip("/")
    if not trimmed:
        return "/*.txt"
    name = f"./{trimmed}" if trimmed.startswith("-") else trimmed
    return f"{shlex.quote(name)}/*.txt"


def _collect_sources(files: list[str], pipe_unread: bool) -> list[_Source]:
    """Reads each named file, then stdin when it is requested.

    ``pipe_unread`` is true when stdin is a pipe or socket that is not read
    because files were named.
    """
    real_files = [f for f in files if f != "-"]
    sources: list[_Source] = []

    for f in real_files:
        try:
            with open(f, "rb") as fh:
                data = fh.read()
        except OSError:
            # The path exists, so "check the path" would send the user the wrong way.
            if os.path.isdir(f):
                raise _UsageError(
                    f"'{f}' is a directory, and directories are not scanned."
                    f" Name the files in it:\n  aicomply scan {_files_glob(f)}"
                ) from None
            raise _UsageError(
                f"cannot read '{f}' (check the path). Try 'aicomply --help'."
            ) from None
        # UTF-32, UTF-16 or UTF-8 without the mark when the file starts with
        # that byte order mark, else UTF-8, with universal newlines. A byte
        # sequence the encoding cannot decode becomes U+FFFD and the rest is
        # scanned, as in the TS CLI.
        content = io.TextIOWrapper(
            io.BytesIO(data), encoding=_bom_encoding(data) or "utf-8", errors="replace"
        ).read()
        sources.append(_Source(label=f, content=content, byte_count=len(data)))

    if _stdin_requested(files):
        if sys.stdin.isatty():
            raise _UsageError(
                "no input. Pass a file or pipe content:\n"
                "  aicomply scan ./file.txt\n"
                '  echo "My SSN is 123-45-6789" | aicomply scan'
            )
        content, byte_count = _read_stdin()
        sources.append(_Source(label="(stdin)", content=content, byte_count=byte_count))

    # comply() runs no layer on empty content and returns CLEAN, so a run in
    # which no input carried a byte would print a verdict nothing reached.
    # Files come first in ``sources``, then stdin. A pipe or socket left unread
    # can hold the content meant for the scan, so the line that says stdin was
    # not read follows the error, as it follows a report.
    if all(s.byte_count == 0 for s in sources):
        empty = [
            f"{s.label} is 0 bytes" if i < len(real_files) else f"{s.label} delivered 0 bytes"
            for i, s in enumerate(sources)
        ]
        note = f"\naicomply: {_STDIN_NOT_READ}" if pipe_unread else ""
        raise _UsageError("no input: " + ", ".join(empty) + note)

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
    ``column`` is one plus the number of code points between the last of them
    and ``original_start``, the count the TypeScript CLI prints. A Python
    string is indexed by code point, so ``column`` is ``original_start`` minus
    the index of that ``\\n`` (taken as -1 on the first line). Only ``\\n``
    ends a line, so a ``\\r`` stays the last character of its line. None when
    there is no position to locate.
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


def _in_input_order(
    content: str, violations: list[Violation]
) -> list[tuple[Violation, tuple[int, int] | None]]:
    """The findings of one input in the order they appear in it: by line, then
    by column. A finding without a location, such as a Guard finding, follows
    the located ones. ``list.sort`` is stable, so findings at the same place
    keep the order comply() gave them.
    """
    located = [(v, _locate_finding(content, v)) for v in violations]
    located.sort(key=lambda pair: (pair[1] is None, pair[1] or (0, 0)))
    return located


def _render_human(sources: list[_Source], results: list[ComplyResult]) -> None:
    out = sys.stdout
    any_guard = False
    total_findings = 0
    worst = "CLEAN"

    # The type column is as wide as the longest type printed, and at least 12
    # characters: a Guard class such as exfiltration_pattern (20 characters) is
    # longer than any pattern class.
    type_width = max(
        [12]
        + [
            len(v.type)
            for src, res in zip(sources, results)
            if src.byte_count > 0 and res.verdict != "CLEAN"
            for v in res.violations
        ]
    )

    out.write("\n")
    for src, res in zip(sources, results):
        if src.byte_count == 0:
            # No layer ran on it, so it gets no verdict and adds none to the total.
            out.write(f"  EMPTY      {src.label}   0 bytes, nothing to classify\n\n")
            continue
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
        for v, loc in _in_input_order(src.content, res.violations):
            view = f"  view {v.view}" if v.view and v.view != "normalized" else ""
            where = f"  line {loc[0]} col {loc[1]}" if loc else ""
            out.write(
                f"    {v.type:<{type_width}} {_MASKED_VALUE:<18} confidence {v.confidence:.2f}  "
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
            # An input of 0 bytes was not classified: its "verdict" is null and
            # its "layers" is [].
            "bytes": src.byte_count,
            "verdict": None if src.byte_count == 0 else res.verdict,
            "guardActive": _guard_active(res),
            "layers": list(res.layers),
            "findings": [_json_finding(src.content, v) for v in res.violations],
        }
        for src, res in zip(sources, results)
    ]
    # ensure_ascii=False prints "•••" as the TS CLI's JSON.stringify does, not
    # as • escapes, so both CLIs print the same bytes.
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


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

    files = args.files or []
    # A file with content on stdin is a usage error before any scan; a pipe or
    # socket gets one stderr line after the report, or after the no-input error
    # when every named file is 0 bytes.
    unread =None if _stdin_requested(files) else _unread_stdin()
    if unread == "content":
        raise _UsageError(
            "stdin is a file with content and is not read because files were named;"
            " add - to scan it too:\n"
            "  aicomply scan - <files>"
        )

    sources = _collect_sources(files, unread == "stream")
    results = [comply(src.content) for src in sources]
    # An input of 0 bytes was not classified, so the inputs that were decide
    # the verdict and the exit code.
    scanned = [res for src, res in zip(sources, results) if src.byte_count > 0]

    if args.json:
        _render_json(sources, results)
    elif args.quiet:
        worst = (
            "DENY"
            if any(r.verdict == "DENY" for r in scanned)
            else "VIOLATION"
            if any(r.verdict == "VIOLATION" for r in scanned)
            else "CLEAN"
        )
        sys.stdout.write(f"{worst}\n")
    else:
        _render_human(sources, results)

    if unread == "stream":
        # A piped stdout is block-buffered; flushing it first keeps the line
        # after the report where both streams go to one log.
        sys.stdout.flush()
        sys.stderr.write(f"aicomply: {_STDIN_NOT_READ}\n")

    return 1 if any(r.verdict != "CLEAN" for r in scanned) else 0


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
