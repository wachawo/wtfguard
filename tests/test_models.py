#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for severity / verdict models."""

from wtfguard.models import Finding, Severity, Verdict


def test_severity_ordering() -> None:
    assert Severity.CLEAN < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_from_name() -> None:
    assert Severity.from_name("high") == Severity.HIGH
    assert Severity.from_name("CRITICAL") == Severity.CRITICAL


def test_verdict_exit_code_clean() -> None:
    v = Verdict(package="x", version="1.0", severity=Severity.LOW, confidence=1.0)
    assert v.exit_code() == 0


def test_verdict_exit_code_high() -> None:
    v = Verdict(package="x", version="1.0", severity=Severity.HIGH, confidence=0.8)
    assert v.exit_code() == 1


def test_verdict_exit_code_critical() -> None:
    v = Verdict(package="x", version="1.0", severity=Severity.CRITICAL, confidence=0.9)
    assert v.exit_code() == 2


def test_verdict_to_dict_round_trip_keys() -> None:
    finding = Finding(
        rule_id="X",
        severity=Severity.MEDIUM,
        file="setup.py",
        line=1,
        snippet="foo",
        description="bar",
    )
    v = Verdict(package="p", version="1", severity=Severity.MEDIUM, confidence=0.5, findings=[finding])
    d = v.to_dict()
    assert d["severity"] == "medium"
    assert d["confidence"] == 0.5
    assert d["findings"][0]["rule_id"] == "X"
