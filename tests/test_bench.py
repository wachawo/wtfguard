#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the offline FP/FN benchmark runner."""

from __future__ import annotations

import json
from pathlib import Path

from wtfguard.bench import (
    BenchmarkReport,
    FixtureResult,
    classify_fixture,
    format_json,
    format_markdown,
    format_text,
    list_fixtures,
    run_benchmark,
)
from wtfguard.models import Severity


def test_classify_fixture_by_prefix() -> None:
    assert classify_fixture("safe-minimal") == "safe"
    assert classify_fixture("malicious-network") == "malicious"
    assert classify_fixture("random-other") == "unknown"


def test_list_fixtures_with_bundled() -> None:
    fixtures = list_fixtures()
    names = {f.name for f in fixtures}
    assert {"safe-minimal", "malicious-network-setup"}.issubset(names)


def test_list_fixtures_missing_dir(tmp_path: Path) -> None:
    assert list_fixtures(tmp_path / "absent") == []


def test_fixture_result_kind() -> None:
    safe_clean = FixtureResult(name="safe-x", expected="safe", severity=Severity.LOW,
                               findings=[], rule_ids=(), correct=True)
    assert safe_clean.kind == "tn"

    safe_flagged = FixtureResult(name="safe-y", expected="safe", severity=Severity.HIGH,
                                 findings=[], rule_ids=(), correct=False)
    assert safe_flagged.kind == "fp"

    bad_caught = FixtureResult(name="mal-x", expected="malicious", severity=Severity.CRITICAL,
                               findings=[], rule_ids=(), correct=True)
    assert bad_caught.kind == "tp"

    bad_missed = FixtureResult(name="mal-y", expected="malicious", severity=Severity.LOW,
                               findings=[], rule_ids=(), correct=False)
    assert bad_missed.kind == "fn"


def test_run_benchmark_bundled_has_zero_overall_fp_fn() -> None:
    report = run_benchmark()
    assert report.total_safe >= 3
    assert report.total_malicious >= 5
    # Bundled fixtures are calibrated: overall FP/FN must be 0 at HIGH+ threshold.
    assert report.false_positives == 0, f"FP fixtures: {[f.name for f in report.fixtures if f.kind == 'fp']}"
    assert report.false_negatives == 0, f"FN fixtures: {[f.name for f in report.fixtures if f.kind == 'fn']}"


def test_run_benchmark_skips_unprefixed(tmp_path: Path) -> None:
    (tmp_path / "weird-thing").mkdir()
    (tmp_path / "safe-thing").mkdir()
    (tmp_path / "safe-thing" / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")
    report = run_benchmark(tmp_path)
    assert len(report.fixtures) == 1
    assert report.fixtures[0].name == "safe-thing"


def test_report_rates_when_no_fixtures() -> None:
    report = BenchmarkReport()
    assert report.fp_rate == 0.0
    assert report.fn_rate == 0.0


def test_format_text_includes_totals() -> None:
    report = run_benchmark()
    output = format_text(report)
    assert "wtfguard heuristic benchmark" in output
    assert "true positives" in output
    assert "false positives" in output


def test_format_markdown_is_valid() -> None:
    report = run_benchmark()
    output = format_markdown(report)
    assert output.startswith("# wtfguard heuristic benchmark")
    assert "| Rule | TP | FP |" in output


def test_format_json_round_trips() -> None:
    report = run_benchmark()
    output = format_json(report)
    parsed = json.loads(output)
    assert parsed["totals"]["fixtures"] == len(report.fixtures)
    assert parsed["totals"]["false_positives"] == report.false_positives
    assert "rule_activations" in parsed
    assert "fixtures" in parsed


def test_rule_activations_tracked() -> None:
    report = run_benchmark()
    # Each malicious fixture triggers at least one rule we can name
    expected_rules = {"NET_IN_SETUP", "EXEC_OBFUSCATED", "CREDENTIAL_READ",
                      "CMDCLASS_SUBPROCESS", "BUILD_REQ_URL"}
    triggered = set(report.rule_tp.keys())
    assert expected_rules.issubset(triggered)


def test_bundled_fixtures_correct_classification() -> None:
    report = run_benchmark()
    for fixture in report.fixtures:
        assert fixture.correct, (
            f"{fixture.name} (expected {fixture.expected}, got severity "
            f"{fixture.severity.label()}, rules {fixture.rule_ids})"
        )
