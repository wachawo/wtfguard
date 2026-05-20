#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Send a scan-summary notification to a Slack / Discord / generic webhook.

Three payload formats auto-detected by URL pattern:
- hooks.slack.com         → Slack incoming-webhook format (`text`)
- discord.com or
  discordapp.com          → Discord webhook format (`content`)
- anything else           → generic JSON `{worst, total, flagged, ...}`

Set `WTFGUARD_WEBHOOK_FORMAT=slack|discord|generic` to override detection.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import urlparse

import requests

from wtfguard.models import Severity, Verdict

logger = logging.getLogger(__name__)

POST_TIMEOUT = 10
FORMAT_ENV = "WTFGUARD_WEBHOOK_FORMAT"
SLACK = "slack"
DISCORD = "discord"
GENERIC = "generic"

SEVERITY_EMOJI = {
    Severity.CLEAN:    ":white_check_mark:",
    Severity.LOW:      ":information_source:",
    Severity.MEDIUM:   ":warning:",
    Severity.HIGH:     ":x:",
    Severity.CRITICAL: ":rotating_light:",
}


def detect_format(url: str) -> str:
    forced = os.getenv(FORMAT_ENV, "").strip().lower()
    if forced in {SLACK, DISCORD, GENERIC}:
        return forced
    host = urlparse(url).netloc.lower()
    if "hooks.slack.com" in host:
        return SLACK
    if "discord.com" in host or "discordapp.com" in host:
        return DISCORD
    return GENERIC


def build_summary(verdicts: list[Verdict], worst: Severity) -> dict[str, Any]:
    flagged = [v for v in verdicts if v.severity >= Severity.MEDIUM]
    return {
        "worst":         worst.label(),
        "total":         len(verdicts),
        "flagged":       len(flagged),
        "packages_with_high_or_critical": [
            f"{v.package}=={v.version}" for v in verdicts if v.severity >= Severity.HIGH
        ][:20],
    }


def render_text(summary: dict[str, Any]) -> str:
    worst_label = summary["worst"]
    emoji = SEVERITY_EMOJI.get(Severity.from_name(worst_label), "")
    lines = [
        f"{emoji} wtfguard scan complete — worst: *{worst_label.upper()}*",
        f"scanned {summary['total']} package(s), {summary['flagged']} flagged",
    ]
    packages = summary.get("packages_with_high_or_critical") or []
    if packages:
        lines.append("flagged (high+):")
        for spec in packages:
            lines.append(f"  • {spec}")
    return "\n".join(lines)


def post(url: str, verdicts: list[Verdict], worst: Severity) -> bool:
    """POST a scan summary to the webhook. Returns True on 2xx, False otherwise."""
    summary = build_summary(verdicts, worst)
    fmt = detect_format(url)
    text = render_text(summary)

    if fmt == SLACK:
        payload: dict[str, Any] = {"text": text}
    elif fmt == DISCORD:
        payload = {"content": text}
    else:
        payload = summary

    try:
        resp = requests.post(url, json=payload, timeout=POST_TIMEOUT)
        if 200 <= resp.status_code < 300:
            return True
        logger.warning(f"Webhook {url} returned {resp.status_code}: {resp.text[:200]}")
        return False
    except requests.RequestException as exc:
        logger.warning(f"Webhook POST failed: {type(exc).__name__}: {exc}")
        return False


def payload_for(url: str, verdicts: list[Verdict], worst: Severity) -> dict[str, Any]:
    """Return the JSON body that `post` would send. Useful for tests + dry-run."""
    summary = build_summary(verdicts, worst)
    fmt = detect_format(url)
    text = render_text(summary)
    if fmt == SLACK:
        return {"text": text}
    if fmt == DISCORD:
        return {"content": text}
    return summary


def serialise(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
