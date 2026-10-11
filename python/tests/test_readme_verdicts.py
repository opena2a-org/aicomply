"""The README lists only the verdicts this package can return.

``Verdict`` names ``DENY`` to match the TypeScript package, where policy packs,
the Registry supply-chain block and signature verification return it. None of
those is ported, so no code path here constructs a ``DENY`` verdict, and the
README must call it reserved rather than list it beside ``CLEAN`` and
``VIOLATION``. When a ported feature starts returning ``DENY``, the second branch
below fails until the README lists it as a real verdict.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_README = _REPO_ROOT / "python" / "README.md"
PACKAGE_SRC = _REPO_ROOT / "python" / "src" / "aicomply"

# A classifier result built with a DENY verdict: ``verdict="DENY"``. The merge in
# dual_layer only propagates a DENY it is given, so it is not a producer.
_DENY_CONSTRUCTION = re.compile(r"""\bverdict\s*=\s*["']DENY["']""")


def _deny_producers() -> list[str]:
    return sorted(
        str(path.relative_to(PACKAGE_SRC))
        for path in PACKAGE_SRC.rglob("*.py")
        if _DENY_CONSTRUCTION.search(path.read_text(encoding="utf-8"))
    )


def _result_field_bullets() -> dict[str, str]:
    """Map each ``ComplyResult`` bullet in the Library API section to its text."""
    readme = PYTHON_README.read_text(encoding="utf-8")
    section = readme.split("\n## Library API\n", 1)[1].split("\n## ", 1)[0]
    field_list = section.split("returns a `ComplyResult` with:\n", 1)[1].split("\n\n", 1)[0]
    bullets = {}
    for bullet in re.split(r"\n(?=- )", field_list.strip()):
        name = re.match(r"- `([^`]+)`", bullet)
        assert name, f"unexpected bullet: {bullet!r}"
        bullets[name.group(1)] = " ".join(bullet.split())
    return bullets


def test_readme_verdict_list_matches_the_verdicts_the_code_returns():
    bullets = _result_field_bullets()
    verdict = bullets["verdict"]
    audit = bullets["original_content"]
    producers = _deny_producers()

    if not producers:
        assert 'or `"DENY"`' not in verdict, verdict
        assert '`"DENY"` is reserved' in verdict, verdict
        assert "never returns it" in verdict, verdict
        assert "omitted on `DENY`" not in audit, audit
        assert "always set today" in audit, audit
    else:
        assert "reserved" not in verdict, (
            f"{producers} construct a DENY verdict; list it in the README as one"
        )
