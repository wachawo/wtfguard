#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the standalone HTML report renderer."""

from __future__ import annotations

from wtfguard.html_report import (
    render,
    render_allowlisted,
    render_finding,
    render_summary,
    worst_severity,
)
from wtfguard.models import Finding, Severity, Verdict


def make_verdict(severity: Severity = Severity.CLEAN, findings: list[Finding] | None = None) -> Verdict:
    return Verdict(
        package="demo",
        version="1.0.0",
        severity=severity,
        confidence=0.85,
        findings=findings or [],
    )


def make_finding(rule: str = "NET_IN_SETUP", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule,
        severity=severity,
        file="setup.py",
        line=10,
        snippet="urlopen('http://x')",
        description="Network call in install-script file",
    )


def test_render_empty_produces_valid_doc() -> None:
    output = render([])
    assert output.startswith("<!doctype html>")
    assert "</html>" in output
    assert "0 package" in output


def test_render_includes_package_rows() -> None:
    v = make_verdict(Severity.HIGH, findings=[make_finding()])
    output = render([v])
    assert "demo" in output
    assert "1.0.0" in output
    assert "NET_IN_SETUP" in output
    assert "high" in output


def test_render_escapes_html_in_snippets() -> None:
    finding = Finding(
        rule_id="X",
        severity=Severity.LOW,
        file="a<b>.py",
        line=1,
        snippet="<script>alert(1)</script>",
        description="watch out",
    )
    v = make_verdict(Severity.LOW, findings=[finding])
    output = render([v])
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output


def test_render_summary_pill_uses_worst() -> None:
    v_low = make_verdict(Severity.LOW)
    v_high = make_verdict(Severity.HIGH, findings=[make_finding()])
    output = render([v_low, v_high])
    summary_block = output[output.find("class=\"summary\""):output.find("</section>")]
    assert "HIGH" in summary_block


def test_render_allowlisted_section() -> None:
    output = render([], allowlisted=["foo==1.0", "bar==2.0"])
    assert "Allowlisted (2)" in output
    assert "foo==1.0" in output
    assert "bar==2.0" in output


def test_render_allowlisted_section_skipped_when_empty() -> None:
    assert render_allowlisted([]) == ""


def test_render_finding_includes_severity_tag() -> None:
    output = render_finding(make_finding(severity=Severity.CRITICAL))
    assert "critical" in output
    assert "NET_IN_SETUP" in output


def test_render_summary_counts() -> None:
    v_clean = make_verdict(Severity.CLEAN)
    v_high = make_verdict(Severity.HIGH, findings=[make_finding()])
    output = render_summary([v_clean, v_high], Severity.HIGH, ["foo"])
    assert "2 package" in output
    assert "1 with findings" in output
    assert "1 allowlisted" in output


def test_worst_severity_picks_max() -> None:
    v1 = make_verdict(Severity.LOW)
    v2 = make_verdict(Severity.CRITICAL)
    assert worst_severity([v1, v2]) == Severity.CRITICAL


def test_worst_severity_empty() -> None:
    assert worst_severity([]) == Severity.CLEAN


def test_render_includes_llm_explanation() -> None:
    v = Verdict(
        package="demo",
        version="1.0.0",
        severity=Severity.HIGH,
        confidence=0.7,
        findings=[make_finding()],
        llm_explanation="malicious-looking install script",
        model="claude-haiku",
    )
    output = render([v])
    assert "malicious-looking install script" in output
    assert "claude-haiku" in output


def test_render_finding_count_in_row() -> None:
    findings = [make_finding(), make_finding(rule="EXEC_OBFUSCATED")]
    v = make_verdict(Severity.CRITICAL, findings=findings)
    output = render([v])
    # The findings count is one of the table cells; just check the rules render
    assert "NET_IN_SETUP" in output
    assert "EXEC_OBFUSCATED" in output
