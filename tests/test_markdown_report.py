#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Markdown report renderer."""

from __future__ import annotations

from wtfguard.markdown_report import render, render_finding, render_verdict, worst_severity
from wtfguard.models import Finding, Severity, Verdict


def make_finding(rule: str = "NET_IN_SETUP", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule,
        severity=severity,
        file="setup.py",
        line=10,
        snippet="urlopen('http://x')",
        description="Network call in install-script file",
    )


def make_verdict(severity: Severity = Severity.HIGH, findings: list[Finding] | None = None) -> Verdict:
    return Verdict(
        package="demo",
        version="1.0.0",
        severity=severity,
        confidence=0.85,
        findings=findings or [make_finding()],
    )


def test_empty_render_still_has_header() -> None:
    output = render([])
    assert "wtfguard supply-chain audit" in output
    assert "Worst severity:" in output


def test_render_includes_summary_table() -> None:
    output = render([make_verdict(Severity.HIGH)])
    assert "| Package | Version | Severity | Findings |" in output
    assert "`demo`" in output
    assert "`1.0.0`" in output


def test_render_includes_findings_section() -> None:
    output = render([make_verdict(Severity.HIGH)])
    assert "### Findings" in output
    assert "NET_IN_SETUP" in output
    assert "<details>" in output


def test_render_omits_findings_section_when_no_findings() -> None:
    verdict = Verdict(package="x", version="1", severity=Severity.CLEAN, confidence=1.0)
    output = render([verdict])
    assert "### Findings" not in output


def test_worst_severity_picks_max() -> None:
    v1 = make_verdict(Severity.LOW, findings=[make_finding(severity=Severity.LOW)])
    v2 = make_verdict(Severity.CRITICAL, findings=[make_finding(severity=Severity.CRITICAL)])
    assert worst_severity([v1, v2]) == Severity.CRITICAL


def test_worst_severity_empty() -> None:
    assert worst_severity([]) == Severity.CLEAN


def test_render_allowlisted_section() -> None:
    output = render([], allowlisted=["foo==1.0", "bar==2.0"])
    assert "### Allowlisted" in output
    assert "`foo==1.0`" in output


def test_render_finding_escapes_backticks() -> None:
    finding = Finding(
        rule_id="X",
        severity=Severity.LOW,
        file="x.py",
        line=1,
        snippet="value with `backticks`",
        description="x",
    )
    output = render_finding(finding)
    assert "\\`backticks\\`" in output


def test_render_verdict_collapsible() -> None:
    output = render_verdict(make_verdict(Severity.HIGH))
    assert "<details>" in output
    assert "</details>" in output


def test_render_includes_emoji_for_severity() -> None:
    output = render([make_verdict(Severity.CRITICAL,
                                  findings=[make_finding(severity=Severity.CRITICAL)])])
    assert ":rotating_light:" in output


def test_render_with_llm_explanation() -> None:
    verdict = Verdict(
        package="demo", version="1.0", severity=Severity.HIGH,
        confidence=0.8, findings=[make_finding()],
        llm_explanation="malicious", model="claude-haiku",
    )
    output = render([verdict])
    assert "claude-haiku" in output
    assert "malicious" in output
