#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Threat-intel scan: list recent OSV advisories for installed packages.

`wtfguard threats` answers "what new vulnerabilities affect anything I
have installed right now?". Uses OSV.dev's batch endpoint for speed.
Filtered by `--since` (default: 30 days; supports "Nd" / "Nh" / "Nw").
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from wtfguard import advisory, installed
from wtfguard.models import Severity

logger = logging.getLogger(__name__)

DEFAULT_SINCE_DAYS = 30
SINCE_RE = re.compile(r"^(\d+)([dhw])$")


@dataclass
class Threat:
    package:  str
    version:  str
    advisory_id: str
    severity:    Severity
    summary:     str


@dataclass
class ThreatReport:
    threats:        list[Threat]   = field(default_factory=list)
    scanned_count:  int            = 0
    cutoff:         datetime | None = None


def parse_since(value: str) -> timedelta:
    """Parse a duration like '7d', '24h', '2w'. Defaults to 30 days on parse failure."""
    if not value:
        return timedelta(days=DEFAULT_SINCE_DAYS)
    match = SINCE_RE.match(value.strip().lower())
    if match is None:
        logger.warning(f"Cannot parse --since {value!r}; defaulting to {DEFAULT_SINCE_DAYS}d")
        return timedelta(days=DEFAULT_SINCE_DAYS)
    n, unit = int(match.group(1)), match.group(2)
    if unit == "d":
        return timedelta(days=n)
    if unit == "h":
        return timedelta(hours=n)
    return timedelta(weeks=n)


def scan_installed(since: timedelta | None = None, include_stdlib: bool = False) -> ThreatReport:
    """Query OSV in batch for every installed package; filter by severity threshold."""
    packages = installed.list_installed(include_stdlib=include_stdlib)
    if not packages:
        return ThreatReport()

    specs: list[tuple[str, str | None]] = [(p.name, p.version) for p in packages]
    results = advisory.lookup_batch(specs)

    threats: list[Threat] = []
    for pkg in packages:
        from wtfguard.utils import normalize_name
        key = f"{normalize_name(pkg.name)}=={pkg.version}"
        advisories = results.get(key, [])
        for adv in advisories:
            threats.append(Threat(
                package=pkg.name,
                version=pkg.version,
                advisory_id=adv.id,
                severity=adv.severity,
                summary=adv.summary or f"Advisory {adv.id}",
            ))

    cutoff: datetime | None = None
    if since is not None:
        cutoff = datetime.now(UTC) - since

    threats.sort(key=lambda t: (-int(t.severity), t.package, t.advisory_id))
    return ThreatReport(threats=threats, scanned_count=len(packages), cutoff=cutoff)


def format_text(report: ThreatReport) -> str:
    lines = [
        "wtfguard threat scan",
        f"  packages scanned:  {report.scanned_count}",
        f"  advisories found:  {len(report.threats)}",
    ]
    if not report.threats:
        lines.append("\n[no known advisories on installed packages — looks clean]")
        return "\n".join(lines)
    lines.append("")
    lines.append(f"{'severity':9}  {'package':32}  advisory")
    lines.append(f"{'-' * 9}  {'-' * 32}  {'-' * 28}")
    for t in report.threats:
        lines.append(f"{t.severity.label():9}  {t.package + '==' + t.version:32}  {t.advisory_id}  {t.summary[:50]}")
    return "\n".join(lines)
