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
from dataclasses import dataclass

from . import __version__, comply
from .classifier.guard_client import DEFAULT_NANOMIND_DAEMON_URL
from .types import ComplyResult


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

Detects PII, credentials, and regulated data before your agent ships content to
a hosted LLM. Runs a deterministic regex layer always, plus an optional semantic
Guard layer when a local nanomind-daemon is reachable.

USAGE
  aicomply scan [file...]      Scan files for sensitive content
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings)
  --quiet, -q   Print only the verdict line
  --version,-V  Print version
  --help, -h    This help

EXIT CODES
  0  CLEAN          no findings, safe to forward
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q

The library API is the production surface: https://github.com/opena2a-org/aicomply
"""


def _mask_value(value: str) -> str:
    """Mask a detected value so the CLI never prints a full secret."""
    v = value or ""
    if len(v) <= 4:
        return "•" * (len(v) or 1)
    head = v[:4]
    tail = v[-2:] if len(v) > 8 else ""
    middle = "•" * max(3, len(v) - len(head) - len(tail))
    return f"{head}{middle}{tail}"


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
            out.write("   no PII, credentials, or regulated data detected\n\n")
            continue
        n = len(res.violations)
        out.write(f"   {n} finding{'' if n == 1 else 's'}\n")
        for v in res.violations:
            masked = _mask_value(v.value)
            view = f"  view {v.view}" if v.view and v.view != "normalized" else ""
            out.write(
                f"    {v.type:<12} {masked:<18} confidence {v.confidence:.2f}  "
                f"layer {v.classifier}{view}\n"
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
        out.write("Verdict: CLEAN  ·  safe to forward.\n")
    else:
        out.write(
            f"Verdict: {worst}  ·  {total_findings} "
            f"finding{'' if total_findings == 1 else 's'} across {len(sources)} "
            f"input{'' if len(sources) == 1 else 's'}. "
            "Block, redact, or log before this content reaches an LLM.\n"
        )


def _render_json(sources: list[_Source], results: list[ComplyResult]) -> None:
    payload = [
        {
            "source": src.label,
            "verdict": res.verdict,
            "guardActive": _guard_active(res),
            "findings": [
                {
                    "type": v.type,
                    "maskedValue": _mask_value(v.value),
                    "confidence": v.confidence,
                    "classifier": v.classifier,
                    "view": v.view or "normalized",
                }
                for v in res.violations
            ],
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
