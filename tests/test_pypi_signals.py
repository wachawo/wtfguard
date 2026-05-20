#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for PyPI metadata signal derivation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wtfguard.models import Severity
from wtfguard.pypi_signals import (
    PackageMetadata,
    days_between,
    derive_findings,
    parse_metadata,
    parse_pypi_timestamp,
)

NOW = datetime(2026, 5, 20, tzinfo=UTC)


def make_metadata(**overrides: object) -> PackageMetadata:
    defaults: dict[str, object] = {
        "name":              "demo",
        "latest_version":    "1.0.0",
        "summary":           "demo",
        "project_urls":      {"Homepage": "https://example"},
        "release_count":     10,
        "first_release_at":  NOW - timedelta(days=365),
        "last_release_at":   NOW - timedelta(days=30),
        "latest_file_count": 5,
    }
    defaults.update(overrides)
    return PackageMetadata(**defaults)  # type: ignore[arg-type]


def test_days_between() -> None:
    earlier = datetime(2026, 1, 1, tzinfo=UTC)
    later = datetime(2026, 2, 10, tzinfo=UTC)
    assert days_between(earlier, later) == 40


def test_parse_pypi_timestamp_iso() -> None:
    parsed = parse_pypi_timestamp("2026-05-20T12:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026
    assert parsed.month == 5


def test_parse_pypi_timestamp_with_offset() -> None:
    parsed = parse_pypi_timestamp("2026-05-20T12:00:00+00:00")
    assert parsed is not None


def test_parse_pypi_timestamp_invalid() -> None:
    assert parse_pypi_timestamp("not a date") is None
    assert parse_pypi_timestamp(None) is None
    assert parse_pypi_timestamp("") is None
    assert parse_pypi_timestamp(12345) is None


def test_derive_findings_healthy_package_clean() -> None:
    findings = derive_findings(make_metadata(), now=NOW)
    rule_ids = {f.rule_id for f in findings}
    assert "LOW_RELEASE_COUNT" not in rule_ids
    assert "BRAND_NEW_PACKAGE" not in rule_ids
    assert "STALE_PACKAGE" not in rule_ids


def test_derive_findings_low_release_count_flagged() -> None:
    findings = derive_findings(make_metadata(release_count=1), now=NOW)
    rule_ids = {f.rule_id for f in findings}
    assert "LOW_RELEASE_COUNT" in rule_ids


def test_derive_findings_brand_new_flagged_medium() -> None:
    findings = derive_findings(
        make_metadata(
            release_count=1,
            first_release_at=NOW - timedelta(days=5),
            last_release_at=NOW - timedelta(days=5),
        ),
        now=NOW,
    )
    brand_new = next((f for f in findings if f.rule_id == "BRAND_NEW_PACKAGE"), None)
    assert brand_new is not None
    assert brand_new.severity == Severity.MEDIUM


def test_derive_findings_stale_package_flagged_low() -> None:
    findings = derive_findings(
        make_metadata(
            first_release_at=NOW - timedelta(days=4000),
            last_release_at=NOW - timedelta(days=3000),
        ),
        now=NOW,
    )
    stale = next((f for f in findings if f.rule_id == "STALE_PACKAGE"), None)
    assert stale is not None
    assert stale.severity == Severity.LOW


def test_derive_findings_missing_project_urls() -> None:
    findings = derive_findings(make_metadata(project_urls={}), now=NOW)
    rule_ids = {f.rule_id for f in findings}
    assert "MISSING_PROJECT_URL" in rule_ids


def test_derive_findings_single_file_release() -> None:
    findings = derive_findings(make_metadata(latest_file_count=1), now=NOW)
    rule_ids = {f.rule_id for f in findings}
    assert "SINGLE_FILE_RELEASE" in rule_ids


def test_parse_metadata_extracts_release_dates() -> None:
    raw = {
        "info": {"name": "demo", "version": "2.0", "summary": "x", "project_urls": {}},
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}],
            "2.0": [{"upload_time_iso_8601": "2025-06-15T00:00:00Z"},
                    {"upload_time_iso_8601": "2025-06-15T01:00:00Z"}],
        },
    }
    meta = parse_metadata("demo", raw)
    assert meta.release_count == 2
    assert meta.first_release_at is not None
    assert meta.first_release_at.year == 2024
    assert meta.last_release_at is not None
    assert meta.last_release_at.year == 2025
    assert meta.latest_file_count == 2


def test_parse_metadata_handles_missing_upload_times() -> None:
    raw = {
        "info": {"name": "demo", "version": "1.0"},
        "releases": {"1.0": [{}]},
    }
    meta = parse_metadata("demo", raw)
    assert meta.first_release_at is None
    assert meta.last_release_at is None


def test_pull_pypi_metadata_404() -> None:
    from wtfguard import pypi_signals as ps

    fake_resp = MagicMock()
    fake_resp.status_code = 404
    with patch("wtfguard.pypi_signals.request_with_retry", return_value=fake_resp):
        assert ps.pull_pypi_metadata("ghost") is None


def test_pull_pypi_metadata_network_error() -> None:
    import requests as r

    from wtfguard import pypi_signals as ps

    with patch("wtfguard.pypi_signals.request_with_retry", side_effect=r.ConnectionError("flap")):
        assert ps.pull_pypi_metadata("demo") is None


def test_read_cache_entry_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from wtfguard import pypi_signals as ps

    monkeypatch.setattr("wtfguard.pypi_signals.CACHE_PATH", tmp_path / "absent.json")
    assert ps.read_cache_entry("demo") is None


def test_read_cache_entry_invalid_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from wtfguard import pypi_signals as ps

    cache_path = tmp_path / "cache.json"
    cache_path.write_text("not json", encoding="utf-8")
    monkeypatch.setattr("wtfguard.pypi_signals.CACHE_PATH", cache_path)
    assert ps.read_cache_entry("demo") is None


def test_write_and_read_cache_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from wtfguard import pypi_signals as ps

    cache_path = tmp_path / "cache.json"
    monkeypatch.setattr("wtfguard.pypi_signals.CACHE_PATH", cache_path)

    raw = {
        "info": {"name": "demo", "version": "1.0", "summary": "x", "project_urls": {}},
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-06-01T00:00:00Z"}]},
    }
    meta = ps.parse_metadata("demo", raw)
    ps.write_cache_entry("demo", meta, raw)

    loaded = ps.read_cache_entry("demo")
    assert loaded is not None
    assert loaded.release_count == 1


def test_read_cache_entry_expired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from wtfguard import pypi_signals as ps

    cache_path = tmp_path / "cache.json"
    cache_path.write_text(
        '{"demo": {"cached_at": "2000-01-01T00:00:00+00:00", "raw": {}}}',
        encoding="utf-8",
    )
    monkeypatch.setattr("wtfguard.pypi_signals.CACHE_PATH", cache_path)
    assert ps.read_cache_entry("demo") is None


def test_pull_pypi_metadata_success() -> None:
    from wtfguard import pypi_signals as ps

    raw = {
        "info": {"name": "demo", "version": "1.0", "summary": "x", "project_urls": {}},
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-06-01T00:00:00Z"}]},
    }
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json.return_value = raw

    with patch("wtfguard.pypi_signals.request_with_retry", return_value=fake_resp):
        result = ps.pull_pypi_metadata("demo")
    assert result == raw
