#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the threats module."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from wtfguard.advisory import Advisory
from wtfguard.installed import InstalledPackage
from wtfguard.models import Severity
from wtfguard.threats import (
    DEFAULT_SINCE_DAYS,
    ThreatReport,
    format_text,
    parse_since,
    scan_installed,
)


def test_parse_since_days() -> None:
    assert parse_since("7d") == timedelta(days=7)


def test_parse_since_hours() -> None:
    assert parse_since("48h") == timedelta(hours=48)


def test_parse_since_weeks() -> None:
    assert parse_since("2w") == timedelta(weeks=2)


def test_parse_since_invalid_defaults() -> None:
    assert parse_since("nonsense") == timedelta(days=DEFAULT_SINCE_DAYS)
    assert parse_since("") == timedelta(days=DEFAULT_SINCE_DAYS)


def test_scan_installed_no_packages() -> None:
    with patch("wtfguard.threats.installed.list_installed", return_value=[]):
        report = scan_installed()
    assert report.scanned_count == 0
    assert report.threats == []


def test_scan_installed_no_advisories() -> None:
    pkgs = [InstalledPackage(name="requests", version="2.32.0")]
    with patch("wtfguard.threats.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.threats.advisory.lookup_batch", return_value={"requests==2.32.0": []}):
        report = scan_installed()
    assert report.scanned_count == 1
    assert report.threats == []


def test_scan_installed_with_advisories() -> None:
    pkgs = [InstalledPackage(name="requests", version="2.32.0")]
    advisories = {
        "requests==2.32.0": [
            Advisory(id="GHSA-x", summary="rce", severity=Severity.HIGH, cvss_score=8.0),
        ]
    }
    with patch("wtfguard.threats.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.threats.advisory.lookup_batch", return_value=advisories):
        report = scan_installed()
    assert len(report.threats) == 1
    assert report.threats[0].package == "requests"
    assert report.threats[0].severity == Severity.HIGH


def test_scan_installed_sorts_by_severity() -> None:
    pkgs = [
        InstalledPackage(name="a", version="1.0"),
        InstalledPackage(name="b", version="1.0"),
    ]
    advisories = {
        "a==1.0": [Advisory(id="GHSA-LOW", summary="", severity=Severity.LOW, cvss_score=2.0)],
        "b==1.0": [Advisory(id="GHSA-HIGH", summary="", severity=Severity.CRITICAL, cvss_score=9.5)],
    }
    with patch("wtfguard.threats.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.threats.advisory.lookup_batch", return_value=advisories):
        report = scan_installed()
    assert report.threats[0].severity == Severity.CRITICAL


def test_format_text_no_threats() -> None:
    out = format_text(ThreatReport(scanned_count=5))
    assert "no known advisories" in out


def test_format_text_with_threats() -> None:
    from wtfguard.threats import Threat
    report = ThreatReport(threats=[Threat(
        package="demo", version="1.0", advisory_id="GHSA-1",
        severity=Severity.HIGH, summary="rce",
    )], scanned_count=10)
    out = format_text(report)
    assert "GHSA-1" in out
    assert "demo==1.0" in out


def test_pep503_normalised_lookup_key() -> None:
    pkgs = [InstalledPackage(name="Foo_Bar", version="1.0")]
    advisories = {"foo-bar==1.0": [
        Advisory(id="GHSA-1", summary="", severity=Severity.MEDIUM, cvss_score=5.0),
    ]}
    with patch("wtfguard.threats.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.threats.advisory.lookup_batch", return_value=advisories):
        report = scan_installed()
    assert len(report.threats) == 1
