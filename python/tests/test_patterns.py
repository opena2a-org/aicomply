"""Pattern detection + validator tests (mirror regex/__tests__/regex.test.ts)."""

from __future__ import annotations

import random
import time

import pytest

from aicomply.classifier.regex import classify_with_regex, scan_patterns
from aicomply.classifier.regex.patterns import PatternMatch, drop_overlapping_repeats, luhn_check


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
    assert akia.value == "...8822"  # no leading characters, the last 4 of 20


@pytest.mark.parametrize(
    ("content", "type_", "masked"),
    [
        ("Passport: A123456", "PASSPORT", "*******"),
        ("Patient MRN: 12345678", "MRN", "********"),
        ("Patient MRN: 123456789", "MRN", "...89"),
        ("SSN: 123-45-6789", "SSN", "...89"),
        ("Patient MRN: 123456789012", "MRN", "...12"),
        ("Card 4222222222222 on file", "PAN", "...2222"),
        ("Card 4111 1111 1111 1111 on file", "PAN", "...1111"),
    ],
)
def test_value_masks_no_leading_characters(content: str, type_: str, masked: str) -> None:
    # 8 characters or fewer reveal nothing, 9 to 12 the last 2, 13 or more the last 4.
    res = classify_with_regex(content)
    assert [(v.type, v.value) for v in res.violations] == [(type_, masked)]


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


def _match(value: str, start: int, end: int) -> PatternMatch:
    return PatternMatch(type="SSN", value=value, start=start, end=end, confidence=0.95)


def _kept_comparing_each_pair(matches: list[PatternMatch]) -> list[PatternMatch]:
    """The matches kept when each match is compared with every match kept before it."""
    kept: list[PatternMatch] = []
    for m in matches:
        if not any(m.start < d.end and m.end > d.start and m.value == d.value for d in kept):
            kept.append(m)
    return kept


def _indices(kept: list[PatternMatch], matches: list[PatternMatch]) -> list[int]:
    """The index of each kept match in ``matches``, found by identity: two matches
    can hold the same value and range."""
    index = {id(m): i for i, m in enumerate(matches)}
    return [index[id(m)] for m in kept]


def test_keeps_the_first_of_two_matches_of_one_value_whose_ranges_overlap():
    first = _match("078-05-1120", 4, 15)
    second = _match("078-05-1120", 0, 15)
    assert drop_overlapping_repeats([first, second]) == [first]


def test_keeps_matches_of_one_value_at_separate_ranges_and_of_two_values_at_one_range():
    matches = [_match("a", 5, 10), _match("a", 0, 5), _match("b", 0, 5)]
    assert drop_overlapping_repeats(matches) == matches


def test_keeps_a_match_whose_range_overlaps_only_that_of_a_match_it_drops():
    matches = [_match("a", 0, 4), _match("a", 3, 8), _match("a", 6, 10)]
    assert drop_overlapping_repeats(matches) == [matches[0], matches[2]]


def test_keeps_what_comparing_each_match_with_every_kept_match_keeps_on_2000_random_lists():
    # Seeded, so a failing list can be reproduced.
    rng = random.Random(203)
    dropped = 0
    for _ in range(2000):
        span = 1 + int(rng.random() * 40)
        longest = int(rng.random() * 10)
        values = ["a", "b", "c"][: 1 + int(rng.random() * 3)]
        matches: list[PatternMatch] = []
        for _ in range(int(rng.random() * 30)):
            start = int(rng.random() * span)
            end = start + int(rng.random() * (longest + 1))
            matches.append(_match(values[int(rng.random() * len(values))], start, end))
        expected = _kept_comparing_each_pair(matches)
        assert _indices(drop_overlapping_repeats(matches), matches) == _indices(expected, matches)
        dropped += len(matches) - len(expected)
    # The lists hold overlapping matches of one value, not only separate ones.
    assert dropped > 0


def test_scans_40000_findings_of_one_ssn_and_one_card_number_in_under_3_seconds_of_cpu_time():
    # Each match was compared with every match kept before it, so the time grew
    # with the square of the number of findings: this input took about 20 seconds
    # of CPU time.
    content = "Customer SSN 078-05-1120 paid with 4111 1111 1111 1111\n" * 20_000
    before = time.process_time()
    matches = scan_patterns(content)
    used = time.process_time() - before
    assert len(matches) == 40_000
    assert used < 3
