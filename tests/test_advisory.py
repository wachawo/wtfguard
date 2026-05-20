#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the OSV.dev advisory lookup module."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from wtfguard.advisory import (
    Advisory,
    AdvisoryCache,
    advisory_from_dict,
    advisory_to_dict,
    cvss_to_severity,
    load_cache,
    lookup,
    parse_cvss_score,
    parse_osv_response,
    query_osv,
    save_cache,
    to_findings,
)
from wtfguard.models import Severity


def make_payload(*vulns: dict) -> dict:
    return {"vulns": list(vulns)}


def test_cvss_to_severity_thresholds() -> None:
    assert cvss_to_severity(9.8) == Severity.CRITICAL
    assert cvss_to_severity(7.5) == Severity.HIGH
    assert cvss_to_severity(5.0) == Severity.MEDIUM
    assert cvss_to_severity(2.0) == Severity.LOW
    assert cvss_to_severity(None) == Severity.MEDIUM


def test_parse_cvss_score_from_string_with_trailing_score() -> None:
    # Some advisories include a numeric score as the last `/`-separated token.
    entries = [{"type": "CVSS_V3", "score": "7.5"}]
    assert parse_cvss_score(entries) == 7.5


def test_parse_cvss_score_vector_only_returns_none() -> None:
    # A bare CVSS vector ("CVSS:3.1/AV:N/...") contains no parseable float —
    # every token has a colon. Parser correctly returns None, severity then
    # defaults to MEDIUM (conservative). Important: do not let the parser
    # mistake the CVSS spec version "3.1" for an impact score.
    entries = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}]
    assert parse_cvss_score(entries) is None


def test_parse_cvss_score_numeric() -> None:
    score = parse_cvss_score([{"type": "CVSS_V3", "score": 8.0}])
    assert score == 8.0


def test_parse_cvss_score_none_when_no_data() -> None:
    assert parse_cvss_score(None) is None
    assert parse_cvss_score([]) is None
    assert parse_cvss_score([{"type": "OTHER", "score": 9.0}]) is None


def test_parse_osv_response_extracts_id_and_severity() -> None:
    payload = make_payload({
        "id":       "GHSA-xxxx-yyyy-zzzz",
        "summary":  "Remote code exec",
        "severity": [{"type": "CVSS_V3", "score": 9.8}],
        "aliases":  ["CVE-2024-1234"],
    })
    result = parse_osv_response(payload)
    assert len(result) == 1
    assert result[0].id == "GHSA-xxxx-yyyy-zzzz"
    assert result[0].severity == Severity.CRITICAL
    assert result[0].aliases == ("CVE-2024-1234",)


def test_parse_osv_response_falls_back_to_details() -> None:
    payload = make_payload({"id": "GHSA-1", "details": "long details text"})
    result = parse_osv_response(payload)
    assert result[0].summary == "long details text"


def test_parse_osv_response_skips_empty_id() -> None:
    payload = make_payload({"id": "", "summary": "bad"}, {"id": "GHSA-2", "summary": "ok"})
    assert [a.id for a in parse_osv_response(payload)] == ["GHSA-2"]


def test_parse_osv_response_empty_or_invalid() -> None:
    assert parse_osv_response({}) == []
    assert parse_osv_response({"vulns": "not a list"}) == []
    assert parse_osv_response({"vulns": [None, 1, "x"]}) == []


def test_advisory_serialization_round_trip() -> None:
    a = Advisory(id="GHSA-1", summary="rce", severity=Severity.HIGH, cvss_score=8.0, aliases=("CVE-1",))
    restored = advisory_from_dict(advisory_to_dict(a))
    assert restored == a


def test_query_osv_success() -> None:
    fake_resp = MagicMock()
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json.return_value = make_payload({"id": "GHSA-1", "summary": "rce"})
    with patch("wtfguard.advisory.requests.post", return_value=fake_resp):
        result = query_osv("requests", "2.32.0")
    assert len(result) == 1
    assert result[0].id == "GHSA-1"


def test_query_osv_network_error_returns_empty() -> None:
    import requests as r
    with patch("wtfguard.advisory.requests.post", side_effect=r.ConnectionError("flap")):
        result = query_osv("requests", "2.32.0")
    assert result == []


def test_query_osv_value_error_returns_empty() -> None:
    fake_resp = MagicMock()
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json.side_effect = ValueError("bad json")
    with patch("wtfguard.advisory.requests.post", return_value=fake_resp):
        result = query_osv("requests", "2.32.0")
    assert result == []


def test_cache_round_trip(tmp_path: Path) -> None:
    cache_path = tmp_path / "adv.json"
    cache = AdvisoryCache()
    cache.put("requests==2.32.0", [Advisory(id="GHSA-1", summary="x", severity=Severity.HIGH, cvss_score=8.0)])
    save_cache(cache, cache_path)

    loaded = load_cache(cache_path)
    assert loaded.get("requests==2.32.0") is not None
    assert loaded.get("missing") is None


def test_cache_expiry(tmp_path: Path) -> None:
    cache = AdvisoryCache(entries={"k": {"ts": time.time() - 100_000, "advisories": []}})
    assert cache.get("k") is None


def test_load_cache_missing_returns_empty(tmp_path: Path) -> None:
    assert load_cache(tmp_path / "missing.json").entries == {}


def test_load_cache_unreadable_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "broken.json"
    f.write_text("not json", encoding="utf-8")
    assert load_cache(f).entries == {}


def test_lookup_uses_cache(tmp_path: Path) -> None:
    cache = AdvisoryCache()
    cache.put("requests==2.32.0", [Advisory(id="GHSA-1", summary="x", severity=Severity.HIGH, cvss_score=8.0)])
    with patch("wtfguard.advisory.query_osv") as mock_query:
        result = lookup("requests", "2.32.0", cache=cache)
    mock_query.assert_not_called()
    assert len(result) == 1


def test_lookup_misses_cache_then_persists(tmp_path: Path) -> None:
    cache = AdvisoryCache()
    fake_advisories = [Advisory(id="GHSA-1", summary="x", severity=Severity.HIGH, cvss_score=8.0)]
    with patch("wtfguard.advisory.query_osv", return_value=fake_advisories):
        result = lookup("requests", "2.32.0", cache=cache)
    assert result == fake_advisories
    assert cache.get("requests==2.32.0") == fake_advisories


def test_lookup_unpinned_returns_empty() -> None:
    assert lookup("requests", None) == []
    assert lookup("requests", "") == []


def test_to_findings_includes_id_and_score() -> None:
    advisories = [
        Advisory(id="GHSA-1", summary="rce", severity=Severity.CRITICAL, cvss_score=9.8, aliases=("CVE-1",))
    ]
    findings = to_findings(advisories)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "KNOWN_ADVISORY"
    assert f.severity == Severity.CRITICAL
    assert "GHSA-1" in f.snippet
    assert "9.8" in f.snippet
    assert "CVE-1" in f.snippet


def test_to_findings_empty_input() -> None:
    assert to_findings([]) == []
