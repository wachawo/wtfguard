#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ruff: noqa: RUF001, RUF003
"""Tests for typosquat detection."""

from __future__ import annotations

from pathlib import Path

from wtfguard.models import Severity
from wtfguard.typosquat import (
    check,
    find_near_matches,
    levenshtein,
    load_popular,
)


def test_levenshtein_identical() -> None:
    assert levenshtein("requests", "requests") == 0


def test_levenshtein_single_insertion() -> None:
    assert levenshtein("requests", "requessts") == 1


def test_levenshtein_substitution() -> None:
    assert levenshtein("requests", "raquests") == 1


def test_levenshtein_empty_strings() -> None:
    assert levenshtein("", "") == 0
    assert levenshtein("abc", "") == 3
    assert levenshtein("", "abc") == 3


def test_levenshtein_swapped_args_consistent() -> None:
    assert levenshtein("foo", "foobar") == levenshtein("foobar", "foo")


def test_load_popular_returns_frozenset() -> None:
    popular = load_popular()
    assert isinstance(popular, frozenset)
    assert "requests" in popular
    assert "numpy" in popular


def test_load_popular_missing_file(tmp_path: Path) -> None:
    assert load_popular(tmp_path / "absent.txt") == frozenset()


def test_load_popular_skips_comments_and_blanks(tmp_path: Path) -> None:
    f = tmp_path / "p.txt"
    f.write_text("# header\n\nrequests\n\n# comment\nnumpy\n", encoding="utf-8")
    result = load_popular(f)
    assert result == frozenset({"requests", "numpy"})


def test_find_near_matches_exact_returns_empty() -> None:
    pop = frozenset({"requests", "numpy"})
    assert find_near_matches("requests", pop) == []


def test_find_near_matches_single_typo() -> None:
    pop = frozenset({"requests", "numpy"})
    matches = find_near_matches("requessts", pop)
    assert ("requests", 1) in matches


def test_find_near_matches_sorted_by_distance() -> None:
    pop = frozenset({"requests", "requessts", "reque"})
    matches = find_near_matches("request", pop)
    # `requests` is closer to `request` (d=1) than `requessts` (d=3)
    assert matches[0][1] <= matches[-1][1]


def test_find_near_matches_length_filter() -> None:
    pop = frozenset({"a"})
    # `verylongname` is so far in length that even checking is skipped
    assert find_near_matches("verylongname", pop, max_distance=2) == []


def test_check_short_name_not_flagged() -> None:
    # Names <= SHORT_NAME_LIMIT chars are skipped to avoid noise
    assert check("a") == []
    assert check("xyz") == []


def test_check_legitimate_popular_not_flagged() -> None:
    assert check("requests") == []
    assert check("numpy") == []


def test_check_typosquat_flagged_high_at_distance_1() -> None:
    findings = check("requessts")
    assert len(findings) == 1
    assert findings[0].rule_id == "TYPOSQUAT_CANDIDATE"
    assert findings[0].severity == Severity.HIGH


def test_check_typosquat_flagged_medium_at_distance_2() -> None:
    # `requestaa` vs `requests` = 2 ops (substitute 's'->'a' + insert 'a')
    findings = check("requestaa", popular=frozenset({"requests"}), max_distance=2)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_check_unrelated_name_clean() -> None:
    assert check("totally-unrelated-name-123") == []


def test_check_pep503_normalization() -> None:
    # Mixed case + dots should normalize before comparing
    findings = check("Requestz_Lib", popular=frozenset({"requestz-lib"}))
    # Normalized "requestz-lib" matches popular exactly → no typosquat
    assert findings == []


def test_check_ultralytics_lookalike_flagged() -> None:
    findings = check("ultralyticss", popular=frozenset({"ultralytics"}))
    assert findings
    assert findings[0].severity == Severity.HIGH


def test_confusable_variants_includes_original() -> None:
    from wtfguard.typosquat import confusable_variants
    variants = confusable_variants("requests")
    assert "requests" in variants


def test_confusable_variants_zero_to_o() -> None:
    from wtfguard.typosquat import confusable_variants
    variants = confusable_variants("python0rg")
    assert "pythonorg" in variants


def test_confusable_variants_rn_to_m() -> None:
    from wtfguard.typosquat import confusable_variants
    variants = confusable_variants("modern")
    # 'rn' becomes 'm' → 'modem'
    assert "modem" in variants


def test_check_catches_confusable_zero_for_o() -> None:
    findings = check("python0rg", popular=frozenset({"pythonorg"}))
    assert findings
    assert findings[0].rule_id == "TYPOSQUAT_CANDIDATE"


def test_check_catches_confusable_one_for_l() -> None:
    findings = check("p1easure", popular=frozenset({"pleasure"}))
    assert findings


def test_check_catches_rn_for_m() -> None:
    # `modern-pkg` typed as `modem-pkg` (m vs rn)
    findings = check("modem-pkg", popular=frozenset({"modern-pkg"}))
    assert findings


def test_deunicode_cyrillic_homoglyphs() -> None:
    from wtfguard.typosquat import deunicode
    # `раckаge` with Cyrillic 'а' (U+0430) — looks identical to Latin 'a'
    candidate = "pаckаge"
    assert deunicode(candidate) == "package"


def test_deunicode_greek_homoglyphs() -> None:
    from wtfguard.typosquat import deunicode
    # `rιch` with Greek iota 'ι' (U+03B9) — looks like Latin 'i'
    candidate = "rιch"
    assert deunicode(candidate) == "rich"


def test_deunicode_preserves_pure_ascii() -> None:
    from wtfguard.typosquat import deunicode
    assert deunicode("requests") == "requests"


def test_deunicode_handles_dash_lookalikes() -> None:
    from wtfguard.typosquat import deunicode
    # `acme–utils` with U+2013 en-dash
    assert deunicode("acme–utils") == "acme-utils"


def test_check_catches_cyrillic_homoglyph() -> None:
    # Attacker registers package with Cyrillic 'а' — looks like `requests`
    candidate = "rеquеsts"  # Cyrillic e
    findings = check(candidate, popular=frozenset({"requests"}))
    assert findings


def test_check_catches_greek_homoglyph() -> None:
    candidate = "pρistιne"  # Greek rho / iota → "pristine"
    findings = check(candidate, popular=frozenset({"pristine"}))
    assert findings
