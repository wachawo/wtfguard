#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PyPI metadata signals — a fourth detection axis alongside heuristics,
OSV, and the LLM.

Without downloading the package, what does the PyPI JSON metadata tell us
about its risk profile? Signals:

- BRAND_NEW package: first release < N days ago (typosquat candidates)
- LOW_RELEASE_COUNT: only 1-2 releases ever (potential one-off attack)
- STALE_PACKAGE: last release > N days ago (abandoned + unmaintained)
- MISSING_PROJECT_URL: no homepage / repo URL declared
- SINGLE_FILE_RELEASE: latest version ships exactly one wheel/sdist (vs
  the dozens normal projects publish across platforms)

These are LOW-severity by default — they are heuristic risk amplifiers,
not "block-this-install" signals. The combiner picks them up the same way
heuristics findings are.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from wtfguard.models import Finding, Severity
from wtfguard.pypi import PYPI_JSON_URL, USER_AGENT, request_with_retry
from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)

CACHE_PATH = Path.home() / ".wtfguard" / "pypi-metadata-cache.json"
CACHE_TTL_SECONDS = 24 * 3600

BRAND_NEW_DAYS = 30
STALE_DAYS = 730
LOW_RELEASE_THRESHOLD = 2
METADATA_TIMEOUT = 10

PYPISTATS_RECENT_URL = "https://pypistats.org/api/packages/{name}/recent"
LOW_DOWNLOAD_THRESHOLD = 1000  # last_month downloads below this == suspicious
DOWNLOAD_TIMEOUT = 5


@dataclass(frozen=True)
class PackageMetadata:
    name:             str
    latest_version:   str
    summary:          str
    project_urls:     dict[str, str]
    release_count:    int
    first_release_at: datetime | None
    last_release_at:  datetime | None
    latest_file_count: int


def fetch_metadata(name: str) -> PackageMetadata | None:
    cached = read_cache_entry(name)
    if cached is not None:
        return cached
    raw = pull_pypi_metadata(name)
    if raw is None:
        return None
    metadata = parse_metadata(name, raw)
    write_cache_entry(name, metadata, raw)
    return metadata


def pull_pypi_metadata(name: str) -> dict[str, Any] | None:
    url = PYPI_JSON_URL.format(name=name)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        resp = request_with_retry(url, headers=headers, timeout=METADATA_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]
    except (requests.RequestException, ValueError) as exc:
        logger.warning(f"PyPI metadata fetch failed for {name}: {type(exc).__name__}: {exc}")
        return None


def parse_metadata(name: str, raw: dict[str, Any]) -> PackageMetadata:
    info = raw.get("info") or {}
    releases = raw.get("releases") or {}

    release_dates: list[datetime] = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            ts_raw = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            parsed = parse_pypi_timestamp(ts_raw)
            if parsed is not None:
                release_dates.append(parsed)

    release_dates.sort()
    latest_release = releases.get(info.get("version", ""), [])
    latest_file_count = len(latest_release) if isinstance(latest_release, list) else 0

    return PackageMetadata(
        name=info.get("name") or name,
        latest_version=info.get("version") or "",
        summary=(info.get("summary") or "")[:200],
        project_urls=info.get("project_urls") or {},
        release_count=len(releases),
        first_release_at=release_dates[0] if release_dates else None,
        last_release_at=release_dates[-1] if release_dates else None,
        latest_file_count=latest_file_count,
    )


def parse_pypi_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value.rstrip("Z")
    try:
        parsed = datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except ValueError:
        return None


def derive_findings(meta: PackageMetadata, now: datetime | None = None) -> list[Finding]:
    """Turn package-level metadata into low-severity Finding objects."""
    if now is None:
        now = datetime.now(UTC)

    findings: list[Finding] = []
    display = f"<metadata:{meta.name}>"

    if meta.release_count <= LOW_RELEASE_THRESHOLD:
        findings.append(
            Finding(
                rule_id="LOW_RELEASE_COUNT",
                severity=Severity.LOW,
                file=display,
                line=1,
                snippet=f"{meta.release_count} release(s) on PyPI",
                description=f"Package has only {meta.release_count} release(s); one-shot uploads are a typosquat signal",
            )
        )

    if meta.first_release_at is not None and days_between(meta.first_release_at, now) < BRAND_NEW_DAYS:
        findings.append(
            Finding(
                rule_id="BRAND_NEW_PACKAGE",
                severity=Severity.MEDIUM,
                file=display,
                line=1,
                snippet=f"first release {meta.first_release_at.date()} ({days_between(meta.first_release_at, now)} days ago)",
                description="Package's first release is recent — review carefully before installing",
            )
        )

    if meta.last_release_at is not None and days_between(meta.last_release_at, now) > STALE_DAYS:
        findings.append(
            Finding(
                rule_id="STALE_PACKAGE",
                severity=Severity.LOW,
                file=display,
                line=1,
                snippet=f"last release {meta.last_release_at.date()} ({days_between(meta.last_release_at, now)} days ago)",
                description="Package looks unmaintained — security patches may not arrive promptly",
            )
        )

    if not meta.project_urls:
        findings.append(
            Finding(
                rule_id="MISSING_PROJECT_URL",
                severity=Severity.LOW,
                file=display,
                line=1,
                snippet="no project_urls in PyPI metadata",
                description="No declared homepage or source repository — harder to audit",
            )
        )

    if meta.latest_file_count == 1:
        findings.append(
            Finding(
                rule_id="SINGLE_FILE_RELEASE",
                severity=Severity.LOW,
                file=display,
                line=1,
                snippet=f"{meta.latest_version} ships 1 file",
                description="Release ships a single wheel/sdist (vs the dozens normal projects ship across platforms)",
            )
        )

    return findings


def fetch_download_count(name: str, timeout: int = DOWNLOAD_TIMEOUT) -> int | None:
    """Last-month download count from pypistats.org, or None on any error.

    Cheap signal: a package nobody downloads is either brand-new, abandoned,
    or a typosquat candidate. We do not cache here — callers compose this
    with their own caching layer (we already cache PyPI metadata under
    pypi-metadata-cache.json, downloads are checked separately).
    """
    url = PYPISTATS_RECENT_URL.format(name=name)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning(f"pypistats fetch failed for {name}: {type(exc).__name__}: {exc}")
        return None

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return None
    raw = data.get("last_month")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    return None


def low_download_finding(name: str, threshold: int = LOW_DOWNLOAD_THRESHOLD) -> list[Finding]:
    """Optional download-volume probe — returns LOW_DOWNLOAD_VOLUME if appropriate."""
    if not name:
        return []
    count = fetch_download_count(name)
    if count is None or count >= threshold:
        return []
    return [
        Finding(
            rule_id="LOW_DOWNLOAD_VOLUME",
            severity=Severity.LOW,
            file=f"<metadata:{name}>",
            line=1,
            snippet=f"{count} downloads in last 30 days",
            description=f"Package received only {count} downloads in the last 30 days — niche, abandoned, or typosquat",
        )
    ]


def days_between(earlier: datetime, later: datetime) -> int:
    return int((later - earlier).total_seconds() // 86400)


def signals_for(name: str, now: datetime | None = None) -> list[Finding]:
    """Convenience: fetch metadata then derive findings. Empty list if PyPI is unreachable."""
    if not name:
        return []
    metadata = fetch_metadata(name)
    if metadata is None:
        return []
    return derive_findings(metadata, now)


def read_cache_entry(name: str) -> PackageMetadata | None:
    if not CACHE_PATH.is_file():
        return None
    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    entry = data.get(normalize_name(name))
    if not isinstance(entry, dict):
        return None
    ts = parse_pypi_timestamp(entry.get("cached_at"))
    if ts is None or days_between(ts, datetime.now(UTC)) > CACHE_TTL_SECONDS // 86400:
        return None
    raw = entry.get("raw")
    if not isinstance(raw, dict):
        return None
    return parse_metadata(name, raw)


def write_cache_entry(name: str, metadata: PackageMetadata, raw: dict[str, Any]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if CACHE_PATH.is_file():
        try:
            existing = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                data = existing
        except (OSError, ValueError):
            pass
    data[normalize_name(name)] = {
        "cached_at": datetime.now(UTC).isoformat(),
        "raw":       raw,
    }
    try:
        CACHE_PATH.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Cannot persist PyPI metadata cache: {type(exc).__name__}: {exc}")
