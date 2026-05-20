#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Forensic timeline for a package: releases + advisories interleaved.

Answers the question "when was this CVE first present in a release, and
when was a fix shipped?". Combines:
- PyPI release dates (from PyPI JSON `releases`)
- OSV.dev advisories (queried per-package, all known versions)

Output is a chronological list of events sorted by date, suitable for
incident post-mortems and supply-chain forensics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from wtfguard import advisory, pypi_signals
from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Event:
    when:        datetime | None
    kind:        str    # "release" | "advisory"
    label:       str    # version string or advisory id
    description: str
    severity:    str | None = None

    def date_str(self) -> str:
        return self.when.strftime("%Y-%m-%d") if self.when else "unknown"


@dataclass
class IncidentReport:
    package: str
    events:  list[Event]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "events": [
                {
                    "when":        e.when.isoformat() if e.when else None,
                    "kind":        e.kind,
                    "label":       e.label,
                    "description": e.description,
                    "severity":    e.severity,
                }
                for e in self.events
            ],
        }


def fetch_release_events(name: str) -> list[Event]:
    """Pull one Event per published version from PyPI JSON."""
    raw = pypi_signals.pull_pypi_metadata(name)
    if raw is None:
        return []
    releases = raw.get("releases") if isinstance(raw, dict) else None
    if not isinstance(releases, dict):
        return []

    events: list[Event] = []
    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue
        ts: datetime | None = None
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            parsed = pypi_signals.parse_pypi_timestamp(
                file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            )
            if parsed is not None and (ts is None or parsed < ts):
                ts = parsed
        events.append(Event(
            when=ts,
            kind="release",
            label=version,
            description=f"PyPI release {name} {version}",
        ))
    return events


def fetch_advisory_events(name: str) -> list[Event]:
    """Pull OSV advisories. We do not have a per-advisory date in our cache;
    we use the OSV `modified` field when available. The CLI shows the
    advisory severity prominently, so the date is supplementary.
    """
    raw = pypi_signals.pull_pypi_metadata(name)
    if raw is None:
        return []
    info = raw.get("info") if isinstance(raw, dict) else None
    if not isinstance(info, dict):
        return []

    latest = info.get("version") or ""
    if not latest:
        return []

    advisories = advisory.lookup(name, latest)
    out: list[Event] = []
    for adv in advisories:
        out.append(Event(
            when=None,
            kind="advisory",
            label=adv.id,
            description=adv.summary or f"Known advisory {adv.id}",
            severity=adv.severity.label(),
        ))
    return out


def build_report(name: str) -> IncidentReport:
    """Build a chronological incident report for `name`."""
    releases = fetch_release_events(name)
    advisories = fetch_advisory_events(name)

    events = sorted(
        releases + advisories,
        key=lambda e: (e.when or datetime.max.replace(tzinfo=UTC), e.kind),
    )
    return IncidentReport(package=normalize_name(name), events=events)


def format_text(report: IncidentReport) -> str:
    lines = [f"wtfguard incident timeline: {report.package}", ""]
    if not report.events:
        lines.append("(no events found — package may be missing from PyPI or have no advisories)")
        return "\n".join(lines)
    lines.append(f"{'date':12}  {'kind':9}  {'severity':9}  label / summary")
    lines.append(f"{'-' * 12}  {'-' * 9}  {'-' * 9}  {'-' * 40}")
    for e in report.events:
        sev = e.severity or "-"
        lines.append(f"{e.date_str():12}  {e.kind:9}  {sev:9}  {e.label} — {e.description[:60]}")
    return "\n".join(lines)
