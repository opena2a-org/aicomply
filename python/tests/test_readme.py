"""The Library API sample in ``python/README.md`` prints what its comments say.

Each ``# ...`` comment in the sample is one line of its output, in order, so the
sample is run as written and its printed output is compared with those comments.
"""

from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

PYTHON_README = Path(__file__).resolve().parents[1] / "README.md"
_COMMENT = re.compile(r"(?:^|\s)# (.*)$")


def library_api_sample() -> str:
    readme = PYTHON_README.read_text(encoding="utf-8")
    section = readme.split("\n## Library API\n", 1)[1].split("\n## ", 1)[0]
    return section.split("```python\n", 1)[1].split("\n```", 1)[0]


def test_library_api_sample_prints_its_comments() -> None:
    sample = library_api_sample()
    comments = [m.group(1).rstrip() for m in map(_COMMENT.search, sample.splitlines()) if m]
    assert comments, "the Library API sample has no output comments"

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(sample, str(PYTHON_README), "exec"), {})

    assert out.getvalue().splitlines() == comments
