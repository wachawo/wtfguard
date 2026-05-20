#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for OSV.dev batch lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from wtfguard.advisory import (
    Advisory,
    AdvisoryCache,
    lookup_batch,
    query_osv_batch,
)
from wtfguard.models import Severity


def fake_response(payload: object) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = payload
    return resp


def test_query_osv_batch_empty_input() -> None:
    assert query_osv_batch([]) == []


def test_query_osv_batch_returns_per_query_lists() -> None:
    payload = {
        "results": [
            {"vulns": [{"id": "GHSA-1", "summary": "rce",
                        "severity": [{"type": "CVSS_V3", "score": 8.0}]}]},
            {},  # no vulns for second
            {"vulns": [{"id": "GHSA-2", "summary": "info"}]},
        ]
    }
    with patch("wtfguard.advisory.requests.post", return_value=fake_response(payload)):
        result = query_osv_batch([("a", "1.0"), ("b", "2.0"), ("c", "3.0")])
    assert len(result) == 3
    assert result[0][0].id == "GHSA-1"
    assert result[1] == []
    assert result[2][0].id == "GHSA-2"


def test_query_osv_batch_falls_back_to_id_only_responses() -> None:
    # OSV's batch endpoint sometimes returns just IDs without details
    payload = {"results": [{"vulns": [{"id": "GHSA-bare"}]}]}
    with patch("wtfguard.advisory.requests.post", return_value=fake_response(payload)):
        result = query_osv_batch([("a", "1.0")])
    assert len(result) == 1
    assert result[0][0].id == "GHSA-bare"
    assert result[0][0].severity == Severity.MEDIUM


def test_query_osv_batch_network_error_returns_empty_lists() -> None:
    import requests as r
    with patch("wtfguard.advisory.requests.post", side_effect=r.ConnectionError("flap")):
        result = query_osv_batch([("a", "1.0"), ("b", "2.0")])
    assert result == [[], []]


def test_query_osv_batch_short_response_padded() -> None:
    payload = {"results": [{"vulns": [{"id": "GHSA-1"}]}]}  # only 1 result for 3 queries
    with patch("wtfguard.advisory.requests.post", return_value=fake_response(payload)):
        result = query_osv_batch([("a", "1.0"), ("b", "2.0"), ("c", "3.0")])
    assert len(result) == 3
    assert result[1] == []
    assert result[2] == []


def test_lookup_batch_uses_cache_for_known_entries() -> None:
    cache = AdvisoryCache()
    cache.put("known==1.0", [Advisory(id="GHSA-old", summary="x", severity=Severity.HIGH, cvss_score=8.0)])

    with patch("wtfguard.advisory.query_osv_batch", return_value=[[]]) as mock_batch:
        result = lookup_batch([("known", "1.0"), ("fresh", "2.0")], cache=cache)

    assert result["known==1.0"][0].id == "GHSA-old"
    assert result["fresh==2.0"] == []
    # Only the fresh spec went to the batch endpoint
    mock_batch.assert_called_once_with([("fresh", "2.0")])


def test_lookup_batch_handles_unpinned() -> None:
    cache = AdvisoryCache()
    with patch("wtfguard.advisory.query_osv_batch", return_value=[[]]) as mock_batch:
        result = lookup_batch([("foo", None), ("bar", "1.0")], cache=cache)
    assert result["foo=="] == []
    mock_batch.assert_called_once_with([("bar", "1.0")])


def test_lookup_batch_populates_cache() -> None:
    cache = AdvisoryCache()
    fake_advisories = [[Advisory(id="GHSA-new", summary="x", severity=Severity.MEDIUM, cvss_score=5.0)]]
    with patch("wtfguard.advisory.query_osv_batch", return_value=fake_advisories):
        lookup_batch([("foo", "1.0")], cache=cache)
    assert cache.get("foo==1.0") is not None
    assert cache.get("foo==1.0")[0].id == "GHSA-new"


def test_lookup_batch_pep503_normalizes_key() -> None:
    cache = AdvisoryCache()
    with patch("wtfguard.advisory.query_osv_batch", return_value=[[]]):
        result = lookup_batch([("Foo_Bar", "1.0")], cache=cache)
    # Key uses normalized name
    assert "foo-bar==1.0" in result
