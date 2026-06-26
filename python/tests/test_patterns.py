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


def test_aws_secret_access_key():
    # The AWS secret access key (40-char base64) has no distinctive prefix, so it
    # is matched only in an aws_secret_access_key assignment context. Parity with
    # the TS patterns.ts AWS secret rule. The value is a synthetic 40-char string
    # built at runtime so no credential literal is committed (GitHub push
    # protection flags 40-char AWS secret literals).
    secret = "Ab3dEf6h" * 5  # 40 chars, all [A-Za-z0-9]
    matches = scan_patterns(f"aws_secret_access_key = {secret}")
    values = {m.value for m in matches if m.type == "CREDENTIAL"}
    assert secret in values
    # both the access key id and the secret are reported when both are present
    both = scan_patterns(
        f"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {secret}"
    )
    both_values = {m.value for m in both if m.type == "CREDENTIAL"}
    assert "AKIAIOSFODNN7EXAMPLE" in both_values
    assert secret in both_values
    # a bare 40-char base64 blob without the keyword must not be flagged
    bare = scan_patterns(f"digest: {secret}")
    assert secret not in {m.value for m in bare}


def test_provider_api_keys():
    # Bare provider keys as they appear in tool output / transcripts, not in a
    # key= assignment (parity with the TS patterns.ts CREDENTIAL block).
    anthropic = "sk-ant-api03-" + "A" * 95
    assert "CREDENTIAL" in _types(f"The agent returned {anthropic} in its summary.")
    assert "CREDENTIAL" in _types("sk-proj-" + "B" * 48)
    assert "CREDENTIAL" in _types("sk-or-v1-" + "c" * 48)
    assert "CREDENTIAL" in _types("sk-" + "d" * 48)  # OpenAI legacy
    # near-miss negatives: too-short suffixes must not match
    assert "CREDENTIAL" not in _types("sk-ant-api03-abc")
    assert "CREDENTIAL" not in _types("sk-" + "e" * 12)
    # an adjacent word char must not let a specific key evade (no leading \b)
    assert "CREDENTIAL" in _types("_sk-ant-api03-" + "A" * 95)
    # English words ending in -sk before a long token must not false-positive
    assert "CREDENTIAL" not in _types("risk-" + "A" * 50)
    assert "CREDENTIAL" not in _types("disk-" + "B" * 50)


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
