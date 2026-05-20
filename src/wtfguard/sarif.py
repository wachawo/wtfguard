#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SARIF 2.1.0 report generator.

SARIF (Static Analysis Results Interchange Format) is the format consumed
by GitHub Code Scanning, GitLab SAST, Azure DevOps, and most enterprise
security dashboards. Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from wtfguard import __version__
from wtfguard.models import Finding, Severity, Verdict

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

SARIF_LEVEL: dict[Severity, str] = {
    Severity.CLEAN:    "none",
    Severity.LOW:      "note",
    Severity.MEDIUM:   "warning",
    Severity.HIGH:     "error",
    Severity.CRITICAL: "error",
}


def build_report(verdicts: Iterable[Verdict]) -> dict[str, Any]:
    """Convert a sequence of Verdicts into a single SARIF run document."""
    verdict_list = list(verdicts)
    rules = collect_rules(verdict_list)
    results = list(collect_results(verdict_list))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            "wtfguard",
                        "version":         __version__,
                        "informationUri":  "https://github.com/wachawo/wtfguard",
                        "rules":           rules,
                    }
                },
                "results": results,
            }
        ],
    }


def collect_rules(verdicts: list[Verdict]) -> list[dict[str, Any]]:
    """Deduplicate rules by id across all findings."""
    seen: dict[str, dict[str, Any]] = {}
    for v in verdicts:
        for f in v.findings:
            if f.rule_id in seen:
                continue
            seen[f.rule_id] = {
                "id":                  f.rule_id,
                "shortDescription":    {"text": f.description[:120]},
                "fullDescription":     {"text": f.description},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "warning")},
                "properties":          {"severity": f.severity.label()},
            }
    return sorted(seen.values(), key=lambda r: r["id"])


def collect_results(verdicts: list[Verdict]) -> Iterable[dict[str, Any]]:
    for verdict in verdicts:
        for finding in verdict.findings:
            yield finding_to_result(verdict, finding)


def finding_to_result(verdict: Verdict, finding: Finding) -> dict[str, Any]:
    return {
        "ruleId":  finding.rule_id,
        "level":   SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region":           {"startLine": max(1, finding.line)},
                }
            }
        ],
        "properties": {
            "package":    verdict.package,
            "version":    verdict.version,
            "severity":   finding.severity.label(),
            "confidence": verdict.confidence,
            "snippet":    finding.snippet,
            "diff_hash":  verdict.diff_hash,
        },
    }
