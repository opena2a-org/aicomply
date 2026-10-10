"""The wheel ships ``python/LICENSE`` as ``aicomply-<version>.dist-info/licenses/LICENSE``.

It must be the same Apache License 2.0 text as the repository's root LICENSE, so
the Python package and the npm package carry one license, word for word.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT_LICENSE = _REPO_ROOT / "LICENSE"
PYTHON_LICENSE = _REPO_ROOT / "python" / "LICENSE"


def test_python_license_matches_root_license() -> None:
    assert PYTHON_LICENSE.read_bytes() == ROOT_LICENSE.read_bytes()


def test_python_license_carries_the_apache_section_6_and_9_wording() -> None:
    text = " ".join(PYTHON_LICENSE.read_text(encoding="utf-8").split())
    assert "except as required for reasonable and customary use in describing the origin" in text
    assert "9. Accepting Warranty or Additional Liability." in text
    assert "of your accepting any such warranty or additional liability." in text
    assert "Accepting Warranty or Support" not in text
    assert "warranty or support" not in text
