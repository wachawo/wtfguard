#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the LOW_DOWNLOAD_VOLUME signal via pypistats."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from wtfguard.models import Severity
from wtfguard.pypi_signals import (
    LOW_DOWNLOAD_THRESHOLD,
    fetch_download_count,
    low_download_finding,
)


def fake_response(payload: object, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.raise_for_status = MagicMock()
    resp.json.return_value = payload
    return resp


def test_fetch_download_count_parses_int() -> None:
    payload = {"data": {"last_day": 50, "last_week": 200, "last_month": 800}}
    with patch("wtfguard.pypi_signals.requests.get", return_value=fake_response(payload)):
        assert fetch_download_count("demo") == 800


def test_fetch_download_count_parses_string() -> None:
    payload = {"data": {"last_month": "1234"}}
    with patch("wtfguard.pypi_signals.requests.get", return_value=fake_response(payload)):
        assert fetch_download_count("demo") == 1234


def test_fetch_download_count_404() -> None:
    resp = MagicMock()
    resp.status_code = 404
    with patch("wtfguard.pypi_signals.requests.get", return_value=resp):
        assert fetch_download_count("demo") is None


def test_fetch_download_count_network_error() -> None:
    with patch("wtfguard.pypi_signals.requests.get", side_effect=requests.ConnectionError("flap")):
        assert fetch_download_count("demo") is None


def test_fetch_download_count_malformed_payload() -> None:
    with patch("wtfguard.pypi_signals.requests.get", return_value=fake_response("not a dict")):
        assert fetch_download_count("demo") is None


def test_fetch_download_count_missing_field() -> None:
    payload = {"data": {"last_week": 100}}
    with patch("wtfguard.pypi_signals.requests.get", return_value=fake_response(payload)):
        assert fetch_download_count("demo") is None


def test_low_download_finding_below_threshold() -> None:
    with patch("wtfguard.pypi_signals.fetch_download_count", return_value=50):
        findings = low_download_finding("demo")
    assert len(findings) == 1
    assert findings[0].rule_id == "LOW_DOWNLOAD_VOLUME"
    assert findings[0].severity == Severity.LOW


def test_low_download_finding_at_threshold() -> None:
    with patch("wtfguard.pypi_signals.fetch_download_count", return_value=LOW_DOWNLOAD_THRESHOLD):
        findings = low_download_finding("demo")
    assert findings == []


def test_low_download_finding_above_threshold() -> None:
    with patch("wtfguard.pypi_signals.fetch_download_count", return_value=1_000_000):
        findings = low_download_finding("demo")
    assert findings == []


def test_low_download_finding_none_count() -> None:
    with patch("wtfguard.pypi_signals.fetch_download_count", return_value=None):
        findings = low_download_finding("demo")
    assert findings == []


def test_low_download_finding_empty_name() -> None:
    findings = low_download_finding("")
    assert findings == []


def test_low_download_finding_custom_threshold() -> None:
    with patch("wtfguard.pypi_signals.fetch_download_count", return_value=5):
        findings = low_download_finding("demo", threshold=10)
    assert len(findings) == 1
