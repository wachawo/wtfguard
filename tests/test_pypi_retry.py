#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the PyPI retry/backoff wrapper."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from wtfguard import pypi


def make_response(status: int) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.close = MagicMock()
    return resp


def test_first_try_success() -> None:
    success = make_response(200)
    with patch("wtfguard.pypi.requests.get", return_value=success) as mock_get:
        result = pypi.request_with_retry("http://example", retries=3)
    assert result is success
    assert mock_get.call_count == 1


def test_retries_on_503_then_succeeds() -> None:
    seq = [make_response(503), make_response(503), make_response(200)]
    with patch("wtfguard.pypi.requests.get", side_effect=seq), patch("wtfguard.pypi.time.sleep") as mock_sleep:
        result = pypi.request_with_retry("http://example", retries=3)
    assert result.status_code == 200
    assert mock_sleep.call_count == 2


def test_retries_exhausted_returns_last() -> None:
    seq = [make_response(503), make_response(503), make_response(503)]
    with patch("wtfguard.pypi.requests.get", side_effect=seq), patch("wtfguard.pypi.time.sleep"):
        result = pypi.request_with_retry("http://example", retries=3)
    assert result.status_code == 503


def test_4xx_not_retried() -> None:
    seq = [make_response(404)]
    with patch("wtfguard.pypi.requests.get", side_effect=seq) as mock_get:
        result = pypi.request_with_retry("http://example", retries=3)
    assert result.status_code == 404
    assert mock_get.call_count == 1


def test_connection_error_retried_then_raised() -> None:
    seq = [
        requests.ConnectionError("flap"),
        requests.ConnectionError("flap"),
        requests.ConnectionError("flap"),
    ]
    with patch("wtfguard.pypi.requests.get", side_effect=seq), patch("wtfguard.pypi.time.sleep"), pytest.raises(requests.ConnectionError):
        pypi.request_with_retry("http://example", retries=3)


def test_connection_error_then_success() -> None:
    seq = [requests.ConnectionError("flap"), make_response(200)]
    with patch("wtfguard.pypi.requests.get", side_effect=seq), patch("wtfguard.pypi.time.sleep"):
        result = pypi.request_with_retry("http://example", retries=3)
    assert result.status_code == 200


def test_timeout_is_retried() -> None:
    seq = [requests.Timeout("slow"), make_response(200)]
    with patch("wtfguard.pypi.requests.get", side_effect=seq), patch("wtfguard.pypi.time.sleep") as mock_sleep:
        result = pypi.request_with_retry("http://example", retries=3)
    assert result.status_code == 200
    assert mock_sleep.called


def test_429_is_retried() -> None:
    seq = [make_response(429), make_response(200)]
    with patch("wtfguard.pypi.requests.get", side_effect=seq), patch("wtfguard.pypi.time.sleep"):
        result = pypi.request_with_retry("http://example", retries=3)
    assert result.status_code == 200
