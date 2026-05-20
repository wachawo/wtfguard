#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Known-CVE / GHSA lookup via the OSV.dev public API.

Adds a third detection axis alongside heuristics and the LLM: querying the
OSV.dev aggregated vulnerability database for the exact (name, version)
under audit. Hits are surfaced as findings with rule id KNOWN_ADVISORY.

Caching: results live in a JSON file under ~/.wtfguard/advisory-cache.json
with a 24h TTL — the OSV.dev API allows unauthenticated use but is not
free as a resource, and most advisory data changes infrequently.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from wtfguard.models import Finding, Severity
from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
CACHE_PATH = Path.home() / ".wtfguard" / "advisory-cache.json"
CACHE_TTL_SECONDS = 24 * 3600
REQUEST_TIMEOUT = 10
USER_AGENT = "wtfguard/0.1 (+https://github.com/wachawo/wtfguard)"

CVSS_CRITICAL_FLOOR = 9.0
CVSS_HIGH_FLOOR = 7.0
CVSS_MEDIUM_FLOOR = 4.0


@dataclass(frozen=True)
class Advisory:
    id:           str
    summary:      str
    severity:     Severity
    cvss_score:   float | None
    aliases:      tuple[str, ...] = ()


@dataclass
class AdvisoryCache:
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, key: str) -> list[Advisory] | None:
        entry = self.entries.get(key)
        if entry is None:
            return None
        if time.time() - float(entry.get("ts", 0)) > CACHE_TTL_SECONDS:
            return None
        return [advisory_from_dict(d) for d in entry.get("advisories", [])]

    def put(self, key: str, advisories: list[Advisory]) -> None:
        self.entries[key] = {
            "ts":         time.time(),
            "advisories": [advisory_to_dict(a) for a in advisories],
        }


def advisory_to_dict(a: Advisory) -> dict[str, Any]:
    return {
        "id":         a.id,
        "summary":    a.summary,
        "severity":   a.severity.label(),
        "cvss_score": a.cvss_score,
        "aliases":    list(a.aliases),
    }


def advisory_from_dict(d: dict[str, Any]) -> Advisory:
    return Advisory(
        id=d["id"],
        summary=d.get("summary", ""),
        severity=Severity.from_name(d.get("severity", "medium")),
        cvss_score=d.get("cvss_score"),
        aliases=tuple(d.get("aliases", [])),
    )


def load_cache(path: Path | None = None) -> AdvisoryCache:
    target = path or CACHE_PATH
    if not target.is_file():
        return AdvisoryCache()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        return AdvisoryCache(entries=data if isinstance(data, dict) else {})
    except (OSError, ValueError) as exc:
        logger.warning(f"Advisory cache unreadable {target}: {type(exc).__name__}: {exc}")
        return AdvisoryCache()


def save_cache(cache: AdvisoryCache, path: Path | None = None) -> None:
    target = path or CACHE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_text(json.dumps(cache.entries, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Cannot persist advisory cache {target}: {type(exc).__name__}: {exc}")


def cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= CVSS_CRITICAL_FLOOR:
        return Severity.CRITICAL
    if score >= CVSS_HIGH_FLOOR:
        return Severity.HIGH
    if score >= CVSS_MEDIUM_FLOOR:
        return Severity.MEDIUM
    return Severity.LOW


def parse_cvss_score(severity_list: list[dict[str, Any]] | None) -> float | None:
    if not severity_list:
        return None
    for entry in severity_list:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") not in {"CVSS_V3", "CVSS_V4"}:
            continue
        raw = entry.get("score")
        if isinstance(raw, str):
            for token in raw.split("/"):
                try:
                    return float(token)
                except ValueError:
                    continue
        elif isinstance(raw, (int, float)):
            return float(raw)
    return None


def parse_osv_response(payload: dict[str, Any]) -> list[Advisory]:
    out: list[Advisory] = []
    vulns = payload.get("vulns") or []
    if not isinstance(vulns, list):
        return out
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        vuln_id = str(entry.get("id", "")).strip()
        if not vuln_id:
            continue
        summary = str(entry.get("summary") or entry.get("details") or "")[:400]
        cvss = parse_cvss_score(entry.get("severity"))
        aliases = tuple(str(a) for a in (entry.get("aliases") or []) if isinstance(a, str))
        out.append(
            Advisory(
                id=vuln_id,
                summary=summary,
                severity=cvss_to_severity(cvss),
                cvss_score=cvss,
                aliases=aliases,
            )
        )
    return out


def query_osv(name: str, version: str, timeout: int = REQUEST_TIMEOUT) -> list[Advisory]:
    body = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        resp = requests.post(OSV_QUERY_URL, json=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning(f"OSV query failed for {name}=={version}: {type(exc).__name__}: {exc}")
        return []
    return parse_osv_response(payload)


def lookup(name: str, version: str | None, cache: AdvisoryCache | None = None) -> list[Advisory]:
    """Return advisories for the exact (name, version). Empty for unpinned input."""
    if not version:
        return []
    key = f"{normalize_name(name)}=={version}"
    target_cache = cache if cache is not None else load_cache()
    cached = target_cache.get(key)
    if cached is not None:
        return cached
    advisories = query_osv(name, version)
    target_cache.put(key, advisories)
    if cache is None:
        save_cache(target_cache)
    return advisories


def lookup_batch(
    specs: list[tuple[str, str | None]],
    cache: AdvisoryCache | None = None,
) -> dict[str, list[Advisory]]:
    """Look up advisories for many specs in one HTTP call.

    Returns a dict keyed by `f"{normalized_name}=={version}"`. Specs with an
    unpinned version are returned as empty lists. Cache hits skip the network.
    """
    target_cache = cache if cache is not None else load_cache()
    results: dict[str, list[Advisory]] = {}

    pending: list[tuple[str, str]] = []
    for name, version in specs:
        if not version:
            results[f"{normalize_name(name)}=="] = []
            continue
        key = f"{normalize_name(name)}=={version}"
        cached = target_cache.get(key)
        if cached is not None:
            results[key] = cached
        else:
            pending.append((name, version))

    if pending:
        fetched = query_osv_batch(pending)
        for (name, version), advisories in zip(pending, fetched, strict=True):
            key = f"{normalize_name(name)}=={version}"
            results[key] = advisories
            target_cache.put(key, advisories)
        if cache is None:
            save_cache(target_cache)

    return results


def query_osv_batch(
    specs: list[tuple[str, str]],
    timeout: int = REQUEST_TIMEOUT,
) -> list[list[Advisory]]:
    """Single POST to /v1/querybatch. Returns per-query advisory lists in input order."""
    if not specs:
        return []
    body = {
        "queries": [
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            for name, version in specs
        ]
    }
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        resp = requests.post(OSV_BATCH_URL, json=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning(f"OSV batch query failed: {type(exc).__name__}: {exc}")
        return [[] for _ in specs]

    raw_results = payload.get("results") or []
    out: list[list[Advisory]] = []
    for entry in raw_results:
        if not isinstance(entry, dict):
            out.append([])
            continue
        # batch responses can contain just IDs; the OSV API guarantees that
        # detailed entries appear under "vulns" with id, summary, severity
        # for IDs we need full details for, but for our threshold detection
        # the IDs alone are enough to mark a finding.
        wrapped = {"vulns": entry.get("vulns") or []}
        advisories = parse_osv_response(wrapped)
        if not advisories:
            ids = [v.get("id") for v in (entry.get("vulns") or []) if isinstance(v, dict)]
            advisories = [
                Advisory(id=str(i), summary="", severity=Severity.MEDIUM, cvss_score=None)
                for i in ids if i
            ]
        out.append(advisories)
    while len(out) < len(specs):
        out.append([])
    return out


def to_findings(advisories: list[Advisory], display_path: str = "<advisory>") -> list[Finding]:
    """Turn advisories into Finding objects that fit into the same pipeline."""
    out: list[Finding] = []
    for a in advisories:
        snippet = f"{a.id}"
        if a.cvss_score is not None:
            snippet += f" (CVSS {a.cvss_score:.1f})"
        if a.aliases:
            snippet += f" aka {','.join(a.aliases[:3])}"
        description = a.summary or f"Known advisory {a.id}"
        out.append(
            Finding(
                rule_id="KNOWN_ADVISORY",
                severity=a.severity,
                file=display_path,
                line=1,
                snippet=snippet[:200],
                description=description[:200],
            )
        )
    return out
