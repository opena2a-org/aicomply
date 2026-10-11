"""The Library API sample in ``python/README.md`` prints what its comments say.

Each ``# ...`` comment in the sample is one line of its output, in order, so the
sample is run as written and its printed output is compared with those comments.
The comments are read as tokens, so a ``# `` inside a string literal of the
sample is not taken for one.
The sample runs in a separate interpreter (``python -I -c``) rather than in the
test's own process, so the test has no in-process call that runs a string as
code, which code scanners report.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tokenize
from pathlib import Path

PYTHON_README = Path(__file__).resolve().parents[1] / "README.md"


def library_api_sample() -> str:
    readme = PYTHON_README.read_text(encoding="utf-8")
    section = readme.split("\n## Library API\n", 1)[1].split("\n## ", 1)[0]
    return section.split("```python\n", 1)[1].split("\n```", 1)[0]


def output_comments(sample: str) -> list[str]:
    """The text of each ``# ...`` comment in ``sample``, in source order."""
    tokens = tokenize.generate_tokens(io.StringIO(sample).readline)
    return [
        token.string[2:].rstrip()
        for token in tokens
        if token.type == tokenize.COMMENT and token.string.startswith("# ")
    ]


def test_output_comments_skip_a_hash_inside_a_string_literal() -> None:
    sample = (
        'print("x # y")  # x # y\n'
        "for v in values:\n"
        '    print(v, "# not output")    # first\n'
        "                                # second\n"
        'print("""a\n# b""")\n'
    )

    assert output_comments(sample) == ["x # y", "first", "second"]


def test_library_api_sample_prints_its_comments() -> None:
    sample = library_api_sample()
    comments = output_comments(sample)
    assert comments, "the Library API sample has no output comments"

    # -I imports the installed aicomply rather than a module in the working
    # directory. The child inherits NODE_ENV and MOCK_NANOMIND_URL from the conftest
    # fixture, so its Guard request goes to the closed port, as the tests' own do.
    run = subprocess.run(
        [sys.executable, "-I", "-c", sample], capture_output=True, text=True, check=False
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == comments
