#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the webhook notifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from wtfguard.models import Severity, Verdict
from wtfguard.webhook import (
    DISCORD,
    GENERIC,
    SLACK,
    build_summary,
    detect_format,
    payload_for,
    post,
    render_text,
)


def make_verdict(name: str = "demo", severity: Severity = Severity.CLEAN) -> Verdict:
    return Verdict(package=name, version="1.0", severity=severity, confidence=1.0)


def test_detect_format_slack() -> None:
    assert detect_format("https://hooks.slack.com/services/T00/B00/XYZ") == SLACK


def test_detect_format_discord() -> None:
    assert detect_format("https://discord.com/api/webhooks/123/abc") == DISCORD
    assert detect_format("https://discordapp.com/api/webhooks/123/abc") == DISCORD


def test_detect_format_generic() -> None:
    assert detect_format("https://example.com/webhook") == GENERIC


def test_detect_format_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WTFGUARD_WEBHOOK_FORMAT", "slack")
    assert detect_format("https://example.com/webhook") == SLACK


def test_build_summary_aggregates() -> None:
    verdicts = [
        make_verdict("ok", Severity.CLEAN),
        make_verdict("bad", Severity.HIGH),
        make_verdict("worse", Severity.CRITICAL),
    ]
    summary = build_summary(verdicts, Severity.CRITICAL)
    assert summary["total"] == 3
    assert summary["flagged"] == 2
    assert summary["worst"] == "critical"
    assert "bad==1.0" in summary["packages_with_high_or_critical"]


def test_render_text_includes_worst() -> None:
    summary = {"worst": "high", "total": 5, "flagged": 2,
               "packages_with_high_or_critical": ["bad==1.0"]}
    text = render_text(summary)
    assert "HIGH" in text
    assert "bad==1.0" in text


def test_payload_for_slack_format() -> None:
    payload = payload_for("https://hooks.slack.com/services/x", [], Severity.CLEAN)
    assert "text" in payload


def test_payload_for_discord_format() -> None:
    payload = payload_for("https://discord.com/api/webhooks/x", [], Severity.CLEAN)
    assert "content" in payload


def test_payload_for_generic() -> None:
    payload = payload_for("https://example.com/x", [], Severity.CLEAN)
    assert "worst" in payload
    assert "text" not in payload
    assert "content" not in payload


def test_post_success() -> None:
    resp = MagicMock()
    resp.status_code = 200
    with patch("wtfguard.webhook.requests.post", return_value=resp):
        assert post("https://example.com/x", [], Severity.CLEAN) is True


def test_post_4xx_returns_false() -> None:
    resp = MagicMock()
    resp.status_code = 400
    resp.text = "bad request"
    with patch("wtfguard.webhook.requests.post", return_value=resp):
        assert post("https://example.com/x", [], Severity.CLEAN) is False


def test_post_network_error_returns_false() -> None:
    import requests as r
    with patch("wtfguard.webhook.requests.post", side_effect=r.ConnectionError("flap")):
        assert post("https://example.com/x", [], Severity.CLEAN) is False
