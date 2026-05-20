#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CycloneDX 1.5 SBOM generator.

CycloneDX is the OWASP-sponsored SBOM format consumed by Dependency-Track,
Snyk, GitLab SBOM upload, AWS Inspector, and most enterprise vulnerability
management platforms. Spec: https://cyclonedx.org/specification/overview/

We emit `bomFormat=CycloneDX`, `specVersion=1.5`, with one `component` per
scanned package and one `vulnerability` per KNOWN_ADVISORY finding. Other
finding types (heuristic, metadata, typosquat, LLM) are surfaced under
`components[*].properties` so SBOM consumers do not lose them.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from wtfguard import __version__
from wtfguard.models import Finding, Severity, Verdict

CYCLONEDX_VERSION = "1.5"
TOOL_VENDOR = "wachawo"
TOOL_NAME = "wtfguard"

CYCLONEDX_SEVERITY = {
    Severity.CLEAN:    "info",
    Severity.LOW:      "low",
    Severity.MEDIUM:   "medium",
    Severity.HIGH:     "high",
    Severity.CRITICAL: "critical",
}


def build_bom(verdicts: Iterable[Verdict]) -> dict[str, Any]:
    """Build a CycloneDX 1.5 document from a sequence of Verdicts."""
    verdict_list = list(verdicts)
    components = [component_for(v) for v in verdict_list]
    vulnerabilities = list(vulnerabilities_for(verdict_list))

    return {
        "bomFormat":     "CycloneDX",
        "specVersion":   CYCLONEDX_VERSION,
        "serialNumber":  f"urn:uuid:{uuid.uuid4()}",
        "version":       1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {
                        "type":    "application",
                        "vendor":  TOOL_VENDOR,
                        "name":    TOOL_NAME,
                        "version": __version__,
                    }
                ]
            },
        },
        "components":      components,
        "vulnerabilities": vulnerabilities,
    }


def component_for(verdict: Verdict) -> dict[str, Any]:
    """One CycloneDX component per package. Non-CVE findings ride along in properties."""
    component: dict[str, Any] = {
        "type":    "library",
        "name":    verdict.package,
        "version": verdict.version,
        "purl":    package_url(verdict.package, verdict.version),
        "bom-ref": package_url(verdict.package, verdict.version),
    }
    properties = list(component_properties(verdict))
    if properties:
        component["properties"] = properties
    return component


def component_properties(verdict: Verdict) -> Iterable[dict[str, str]]:
    yield {"name": "wtfguard:severity",   "value": verdict.severity.label()}
    yield {"name": "wtfguard:confidence", "value": f"{verdict.confidence:.2f}"}
    if verdict.diff_hash:
        yield {"name": "wtfguard:diff_hash", "value": verdict.diff_hash}
    if verdict.model:
        yield {"name": "wtfguard:llm_model", "value": verdict.model}
    if verdict.llm_explanation:
        yield {"name": "wtfguard:llm_explanation", "value": verdict.llm_explanation[:1024]}
    for finding in verdict.findings:
        if finding.rule_id == "KNOWN_ADVISORY":
            continue  # surfaced separately as a vulnerability
        yield {
            "name":  f"wtfguard:finding:{finding.rule_id}",
            "value": f"{finding.severity.label()}|{finding.file}:{finding.line}|{finding.description[:160]}",
        }


def vulnerabilities_for(verdicts: list[Verdict]) -> Iterable[dict[str, Any]]:
    for verdict in verdicts:
        for finding in verdict.findings:
            if finding.rule_id != "KNOWN_ADVISORY":
                continue
            yield vulnerability_entry(verdict, finding)


def vulnerability_entry(verdict: Verdict, finding: Finding) -> dict[str, Any]:
    advisory_id = parse_advisory_id(finding.snippet) or finding.rule_id
    return {
        "id":      advisory_id,
        "source":  {"name": "OSV", "url": f"https://osv.dev/vulnerability/{advisory_id}"},
        "ratings": [
            {
                "source":   {"name": "OSV"},
                "severity": CYCLONEDX_SEVERITY.get(finding.severity, "unknown"),
                "method":   "other",
            }
        ],
        "description": finding.description,
        "affects": [{"ref": package_url(verdict.package, verdict.version)}],
    }


def package_url(name: str, version: str) -> str:
    """Build a Package URL (purl) per https://github.com/package-url/purl-spec."""
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def parse_advisory_id(snippet: str) -> str | None:
    """Extract the first GHSA-/CVE-style token from a finding snippet."""
    for token in snippet.split():
        cleaned = token.strip(",;().")
        if cleaned.upper().startswith(("GHSA-", "CVE-", "PYSEC-")):
            return cleaned
    return None
