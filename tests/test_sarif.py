#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for SARIF 2.1.0 report generation."""

import json

from wtfguard.models import Finding, Severity, Verdict
from wtfguard.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    build_report,
    collect_results,
    collect_rules,
    finding_to_result,
)


def make_verdict(severity: Severity = Severity.HIGH) -> Verdict:
    finding = Finding(
        rule_id="NET_IN_SETUP",
        severity=Severity.HIGH,
        file="setup.py",
        line=12,
        snippet="urlopen('http://x')",
        description="Network call in install-script file",
    )
    return Verdict(
        package="demo",
        version="1.0.0",
        severity=severity,
        confidence=0.85,
        findings=[finding] if severity >= Severity.HIGH else [],
        diff_hash="abc123",
    )


def test_empty_report_still_valid() -> None:
    report = build_report([])
    assert report["version"] == SARIF_VERSION
    assert report["$schema"] == SARIF_SCHEMA
    assert report["runs"][0]["tool"]["driver"]["name"] == "wtfguard"
    assert report["runs"][0]["results"] == []
    assert report["runs"][0]["tool"]["driver"]["rules"] == []


def test_report_with_findings() -> None:
    report = build_report([make_verdict(Severity.HIGH)])
    run = report["runs"][0]
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "NET_IN_SETUP"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "setup.py"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_rules_are_deduplicated() -> None:
    v1 = make_verdict(Severity.HIGH)
    v2 = make_verdict(Severity.HIGH)
    rules = collect_rules([v1, v2])
    assert len(rules) == 1
    assert rules[0]["id"] == "NET_IN_SETUP"


def test_severity_maps_to_sarif_level() -> None:
    severities_and_levels = [
        (Severity.CLEAN, "none"),
        (Severity.LOW, "note"),
        (Severity.MEDIUM, "warning"),
        (Severity.HIGH, "error"),
        (Severity.CRITICAL, "error"),
    ]
    for sev, expected_level in severities_and_levels:
        finding = Finding(
            rule_id="X",
            severity=sev,
            file="x.py",
            line=1,
            snippet="",
            description="d",
        )
        verdict = Verdict(package="p", version="1", severity=sev, confidence=0.9, findings=[finding])
        result = finding_to_result(verdict, finding)
        assert result["level"] == expected_level


def test_result_properties_include_metadata() -> None:
    verdict = make_verdict(Severity.HIGH)
    result = finding_to_result(verdict, verdict.findings[0])
    props = result["properties"]
    assert props["package"] == "demo"
    assert props["version"] == "1.0.0"
    assert props["confidence"] == 0.85
    assert props["diff_hash"] == "abc123"


def test_collect_results_yields_one_per_finding() -> None:
    f1 = Finding(rule_id="A", severity=Severity.MEDIUM, file="x", line=1, snippet="", description="a")
    f2 = Finding(rule_id="B", severity=Severity.HIGH, file="y", line=2, snippet="", description="b")
    verdict = Verdict(package="p", version="1", severity=Severity.HIGH, confidence=0.8, findings=[f1, f2])
    results = list(collect_results([verdict]))
    assert len(results) == 2
    assert {r["ruleId"] for r in results} == {"A", "B"}


def test_report_is_valid_json() -> None:
    report = build_report([make_verdict(Severity.HIGH)])
    serialized = json.dumps(report)
    reparsed = json.loads(serialized)
    assert reparsed == report


def test_zero_line_normalized_to_one() -> None:
    finding = Finding(rule_id="X", severity=Severity.LOW, file="x.py", line=0, snippet="", description="d")
    verdict = Verdict(package="p", version="1", severity=Severity.LOW, confidence=1.0, findings=[finding])
    result = finding_to_result(verdict, finding)
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
