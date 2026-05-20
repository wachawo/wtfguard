#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the incident timeline builder."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from wtfguard.advisory import Advisory
from wtfguard.incident import (
    Event,
    IncidentReport,
    build_report,
    fetch_advisory_events,
    fetch_release_events,
    format_text,
)
from wtfguard.models import Severity


def fake_raw_with_releases() -> dict:
    return {
        "info": {"name": "demo", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}],
            "2.0.0": [
                {"upload_time_iso_8601": "2025-06-01T00:00:00Z"},
                {"upload_time_iso_8601": "2025-06-01T01:00:00Z"},
            ],
            "missing-date": [],
        },
    }


def test_fetch_release_events_extracts_dates() -> None:
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=fake_raw_with_releases()):
        events = fetch_release_events("demo")
    versions = {e.label for e in events}
    assert versions == {"1.0.0", "2.0.0"}  # empty release dropped
    by_version = {e.label: e for e in events}
    assert by_version["1.0.0"].when is not None
    assert by_version["1.0.0"].when.year == 2024


def test_fetch_release_events_picks_earliest_file() -> None:
    raw = {
        "info": {"name": "demo", "version": "1.0"},
        "releases": {
            "1.0": [
                {"upload_time_iso_8601": "2025-06-01T02:00:00Z"},
                {"upload_time_iso_8601": "2025-06-01T00:00:00Z"},
                {"upload_time_iso_8601": "2025-06-01T01:00:00Z"},
            ]
        },
    }
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=raw):
        events = fetch_release_events("demo")
    assert len(events) == 1
    assert events[0].when is not None
    assert events[0].when.hour == 0


def test_fetch_release_events_no_metadata() -> None:
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=None):
        assert fetch_release_events("ghost") == []


def test_fetch_advisory_events_with_hits() -> None:
    raw = {"info": {"name": "demo", "version": "1.0"}, "releases": {}}
    fake_adv = [Advisory(id="GHSA-x", summary="rce", severity=Severity.HIGH, cvss_score=8.0)]
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=raw), \
         patch("wtfguard.incident.advisory.lookup", return_value=fake_adv):
        events = fetch_advisory_events("demo")
    assert len(events) == 1
    assert events[0].kind == "advisory"
    assert events[0].severity == "high"


def test_fetch_advisory_events_no_metadata() -> None:
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=None):
        assert fetch_advisory_events("ghost") == []


def test_build_report_chronological() -> None:
    raw = fake_raw_with_releases()
    fake_adv = [Advisory(id="GHSA-1", summary="x", severity=Severity.CRITICAL, cvss_score=9.5)]
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=raw), \
         patch("wtfguard.incident.advisory.lookup", return_value=fake_adv):
        report = build_report("demo")
    assert isinstance(report, IncidentReport)
    assert report.package == "demo"
    # First event should be the 2024 release; advisory (no date) goes last
    kinds = [(e.kind, e.label) for e in report.events]
    assert kinds[0] == ("release", "1.0.0")
    assert ("advisory", "GHSA-1") in kinds


def test_build_report_missing_package() -> None:
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=None):
        report = build_report("ghost")
    assert report.events == []


def test_format_text_no_events() -> None:
    report = IncidentReport(package="ghost", events=[])
    out = format_text(report)
    assert "no events found" in out


def test_format_text_with_events() -> None:
    events = [
        Event(when=datetime(2024, 1, 1, tzinfo=UTC), kind="release", label="1.0.0", description="release 1.0.0"),
        Event(when=None, kind="advisory", label="GHSA-1", description="rce", severity="high"),
    ]
    report = IncidentReport(package="demo", events=events)
    out = format_text(report)
    assert "1.0.0" in out
    assert "GHSA-1" in out
    assert "high" in out


def test_to_dict_round_trip_keys() -> None:
    event = Event(when=datetime(2024, 1, 1, tzinfo=UTC), kind="release",
                  label="1.0.0", description="x")
    report = IncidentReport(package="demo", events=[event])
    d = report.to_dict()
    assert d["package"] == "demo"
    assert d["events"][0]["label"] == "1.0.0"
    assert d["events"][0]["when"].startswith("2024-01-01")
