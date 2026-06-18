"""Pattern detection + validator tests (mirror regex/__tests__/regex.test.ts)."""

from __future__ import annotations

import pytest

from aicomply.classifier.regex import classify_with_regex, scan_patterns
from aicomply.classifier.regex.patterns import luhn_check


def _types(text: str) -> set[str]:
    return {m.type for m in scan_patterns(text)}


def test_ssn_detected_and_validated():
    assert "SSN" in _types("My SSN is 516-81-3086.")
    # invalid area 000 / 666 / >=900 rejected
    assert "SSN" not in _types("Reference: 000-12-3456.")
    assert "SSN" not in _types("Reference: 666-46-1673.")
    assert "SSN" not in _types("Reference: 923-46-1673.")
    # serial 0000 rejected
    assert "SSN" not in _types("Reference: 402-37-0000.")


def test_pan_luhn_and_iin():
    assert "PAN" in _types("Card 5544939082323438 on file.")  # valid mastercard, luhn ok
    assert "PAN" not in _types("Transaction 4910830182038450 cleared.")  # non-luhn
    assert "PAN" not in _types("Transaction 824964466228 cleared.")  # too short
    assert "PAN" not in _types("Transaction 36752284833978891464 cleared.")  # too long


def test_credentials():
    assert "CREDENTIAL" in _types("key AKIA7IEO7LTOBPA48822 leaked")
    ghp_fine = "github_pat_" + "A" * 82  # fine-grained token: 82 chars after prefix
    assert "CREDENTIAL" in _types(f"token {ghp_fine} here")
    assert "CREDENTIAL" in _types("Authorization: Bearer abcdefghij0123456789KLMNOP")
    assert "CREDENTIAL" in _types("api_key=AbCdEf0123456789ZZ")
    # negatives: too short / placeholder / docs-mention
    assert "CREDENTIAL" not in _types("Bearer X")
    assert "CREDENTIAL" not in _types("Use placeholder ${API_KEY} during local dev.")
    assert "CREDENTIAL" not in _types("Set api_key to your actual key in production.")
    assert "CREDENTIAL" not in _types("AKIA9OK6Q4TR")  # akia-short


def test_cui():
    assert "CUI" in _types("Document marked CUI//BASIC here.")
    assert "CUI" in _types("CONTROLLED UNCLASSIFIED INFORMATION applies.")
    assert "CUI" not in _types("The CUI program trains analysts.")  # prose-mention


def test_iban_mod97():
    assert "IBAN" in _types("Wire to DE53083497798682044097 today.")
    # bad checksum should fail mod-97
    assert "IBAN" not in _types("Wire to DE00083497798682044097 today.")


def test_mrn_requires_digit():
    assert "MRN" in _types("Patient MRN-L704K9 admitted.")
    assert "MRN" not in _types("MRN training is required for new admits.")  # no digit


def test_npi_luhn_prefix():
    assert "NPI" in _types("Provider NPI: 6928576605 on record.")
    # flipped a digit -> bad luhn
    assert "NPI" not in _types("Provider NPI: 6928576606 on record.")


def test_passport_needs_context():
    assert "PASSPORT" in _types("Passport-SW232303697 issued.")
    assert "PASSPORT" not in _types("Order SW232303697 shipped.")  # no context keyword


def test_luhn_check_unit():
    assert luhn_check("5544939082323438") is True
    assert luhn_check("4910830182038450") is False
    assert luhn_check("not-digits") is False


def test_value_is_redacted_not_raw():
    res = classify_with_regex("key AKIA7IEO7LTOBPA48822 leaked")
    akia = next(v for v in res.violations if v.type == "CREDENTIAL")
    assert "AKIA7IEO7LTOBPA48822" not in akia.value  # never the raw secret
    assert akia.value.startswith("AKIA") and akia.value.endswith("22")


def test_clean_content_returns_clean():
    res = classify_with_regex("The weather is nice. Order 300843 shipped.")
    assert res.verdict == "CLEAN"
    assert res.violations == []


@pytest.mark.parametrize(
    "text",
    [
        "Reference: 402-37-0000.",  # ssn near-miss
        "Transaction 7758291431283880 cleared.",  # pan invalid-iin
    ],
)
def test_known_negatives(text):
    assert _types(text) == set()
