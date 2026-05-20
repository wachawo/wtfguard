#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pre-download sdists for later --offline scans.

In air-gapped CI workflows you need every sdist on disk before the
network goes away. `wtfguard prefetch <requirements>` parses any lockfile
format the CLI already supports, then downloads each (name, version) into
a target directory using the existing pypi fetcher (which verifies the
published SHA256 by default).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from wtfguard import pypi

logger = logging.getLogger(__name__)

DEFAULT_PREFETCH_DIR = Path.home() / ".wtfguard" / "prefetch"


@dataclass
class PrefetchReport:
    succeeded: list[str] = field(default_factory=list)
    skipped:   list[str] = field(default_factory=list)
    failed:    list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.succeeded) + len(self.skipped) + len(self.failed)


def run(
    specs: Iterable[tuple[str, str | None]],
    dest: Path | None = None,
) -> PrefetchReport:
    """Download every pinned spec into `dest`. Unpinned specs are skipped.

    Returns a report listing per-spec outcome. We do NOT extract — that
    happens lazily on subsequent scans. The intention is to populate the
    PyPI download cache before going offline.
    """
    target = dest or DEFAULT_PREFETCH_DIR
    target.mkdir(parents=True, exist_ok=True)

    report = PrefetchReport()
    for name, version in specs:
        spec_label = f"{name}=={version or 'latest'}"
        if not version:
            logger.info(f"skipping unpinned {name}")
            report.skipped.append(spec_label)
            continue
        try:
            release = pypi.fetch_release(name, version)
        except (LookupError, OSError) as exc:
            report.failed.append((spec_label, f"{type(exc).__name__}: {exc}"))
            continue

        archive = release.pick_sdist() or release.pick_wheel()
        if archive is None:
            report.failed.append((spec_label, "no sdist or wheel published"))
            continue

        try:
            pypi.download_file(archive, target / f"{name}-{version}")
            report.succeeded.append(spec_label)
        except (OSError, Exception) as exc:
            report.failed.append((spec_label, f"{type(exc).__name__}: {exc}"))

    return report


def format_text(report: PrefetchReport) -> str:
    lines = [
        "wtfguard prefetch summary",
        f"  succeeded: {len(report.succeeded)}",
        f"  skipped:   {len(report.skipped)}",
        f"  failed:    {len(report.failed)}",
    ]
    if report.failed:
        lines.append("")
        lines.append("failures:")
        for spec, reason in report.failed:
            lines.append(f"  - {spec}: {reason}")
    return "\n".join(lines)
