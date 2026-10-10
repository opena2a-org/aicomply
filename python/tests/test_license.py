"""The wheel ships ``python/LICENSE`` as ``aicomply-<version>.dist-info/licenses/LICENSE``.

It must be the same Apache License 2.0 text as the repository's root LICENSE, so
the Python package and the npm package carry one license, word for word. Byte
equality alone would let an identical edit to both files pass, so the text is
also pinned to the canonical file Apache publishes.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT_LICENSE = _REPO_ROOT / "LICENSE"
PYTHON_LICENSE = _REPO_ROOT / "python" / "LICENSE"
PYTHON_README = _REPO_ROOT / "python" / "README.md"

# sha256 of https://www.apache.org/licenses/LICENSE-2.0.txt. That file's appendix
# carries the placeholder line below where ours names the copyright holder.
# Verify: curl -s https://www.apache.org/licenses/LICENSE-2.0.txt | shasum -a 256
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
APACHE_COPYRIGHT_PLACEHOLDER = "   Copyright [yyyy] [name of copyright owner]"
_COPYRIGHT_LINE = re.compile(r"^   Copyright \S.*$", re.MULTILINE)


def canonical_license_sha256(text: str) -> str:
    """Hash ``text`` with its one appendix copyright line put back to Apache's placeholder."""
    body, count = _COPYRIGHT_LINE.subn(APACHE_COPYRIGHT_PLACEHOLDER, text)
    assert count == 1, f"expected one appendix copyright line, found {count}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_python_license_matches_root_license() -> None:
    assert PYTHON_LICENSE.read_bytes() == ROOT_LICENSE.read_bytes()


def test_license_is_the_canonical_apache_2_0_text_apart_from_the_copyright_line() -> None:
    text = PYTHON_LICENSE.read_text(encoding="utf-8")
    assert canonical_license_sha256(text) == APACHE_2_0_SHA256


def test_canonical_hash_catches_an_edited_clause() -> None:
    text = PYTHON_LICENSE.read_text(encoding="utf-8")
    clause = "9. Accepting Warranty or Additional Liability."
    edited = text.replace(clause, "9. Accepting Warranty.")
    assert edited != text
    assert canonical_license_sha256(edited) != APACHE_2_0_SHA256


def test_python_license_carries_the_apache_section_6_and_9_wording() -> None:
    text = " ".join(PYTHON_LICENSE.read_text(encoding="utf-8").split())
    assert "except as required for reasonable and customary use in describing the origin" in text
    assert "9. Accepting Warranty or Additional Liability." in text
    assert "of your accepting any such warranty or additional liability." in text
    assert "Accepting Warranty or Support" not in text
    assert "warranty or support" not in text


def test_python_readme_license_section_links_the_license_file() -> None:
    # PyPI renders this README, where a relative link does not resolve, so the
    # link is the absolute URL of python/LICENSE.
    readme = PYTHON_README.read_text(encoding="utf-8")
    section = readme.split("\n## License\n", 1)[1].split("\n## ", 1)[0]
    assert "(https://github.com/opena2a-org/aicomply/blob/main/python/LICENSE)" in section
