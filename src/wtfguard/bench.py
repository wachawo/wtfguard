#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline FP/FN benchmark runner against bundled golden fixtures.

The single most important metric for wtfguard is false-positive rate on
legitimate packages, not detection rate on known malicious code. This
module runs the heuristic engine against a bundled `golden/` directory
of safe and malicious fixtures and reports both.

Output formats: text, markdown, json.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wtfguard import heuristics
from wtfguard.models import Finding, Severity

logger = logging.getLogger(__name__)

GOLDEN_DIR = Path(__file__).parent / "golden"
EXPECT_SAFE_PREFIX = "safe-"
EXPECT_MALICIOUS_PREFIX = "malicious-"


@dataclass(frozen=True)
class FixtureResult:
    name:        str
    expected:    str
    severity:    Severity
    findings:    list[Finding]
    rule_ids:    tuple[str, ...]
    correct:     bool

    @property
    def kind(self) -> str:
        """One of: tp (caught malicious), fn (missed malicious), tn (clean safe), fp (flagged safe)."""
        if self.expected == "malicious":
            return "tp" if self.severity >= Severity.HIGH else "fn"
        return "fp" if self.severity >= Severity.HIGH else "tn"


@dataclass
class BenchmarkReport:
    fixtures:      list[FixtureResult] = field(default_factory=list)
    rule_fp:       dict[str, int]      = field(default_factory=lambda: defaultdict(int))
    rule_tp:       dict[str, int]      = field(default_factory=lambda: defaultdict(int))

    @property
    def total_safe(self) -> int:
        return sum(1 for f in self.fixtures if f.expected == "safe")

    @property
    def total_malicious(self) -> int:
        return sum(1 for f in self.fixtures if f.expected == "malicious")

    @property
    def true_positives(self) -> int:
        return sum(1 for f in self.fixtures if f.kind == "tp")

    @property
    def true_negatives(self) -> int:
        return sum(1 for f in self.fixtures if f.kind == "tn")

    @property
    def false_positives(self) -> int:
        return sum(1 for f in self.fixtures if f.kind == "fp")

    @property
    def false_negatives(self) -> int:
        return sum(1 for f in self.fixtures if f.kind == "fn")

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total_safe if self.total_safe else 0.0

    @property
    def fn_rate(self) -> float:
        return self.false_negatives / self.total_malicious if self.total_malicious else 0.0


def list_fixtures(golden_dir: Path | None = None) -> list[Path]:
    target = golden_dir or GOLDEN_DIR
    if not target.is_dir():
        return []
    return sorted(p for p in target.iterdir() if p.is_dir())


def classify_fixture(name: str) -> str:
    if name.startswith(EXPECT_SAFE_PREFIX):
        return "safe"
    if name.startswith(EXPECT_MALICIOUS_PREFIX):
        return "malicious"
    return "unknown"


def run_benchmark(golden_dir: Path | None = None) -> BenchmarkReport:
    rules = heuristics.load_rules()
    report = BenchmarkReport()
    for fixture in list_fixtures(golden_dir):
        expected = classify_fixture(fixture.name)
        if expected == "unknown":
            logger.warning(f"Skipping fixture {fixture.name} — no safe-/malicious- prefix")
            continue
        findings = heuristics.scan_directory(fixture, rules)
        severity = heuristics.aggregate_severity(findings)
        rule_ids = tuple(sorted({f.rule_id for f in findings}))
        result = FixtureResult(
            name=fixture.name,
            expected=expected,
            severity=severity,
            findings=findings,
            rule_ids=rule_ids,
            correct=(expected == "malicious") == (severity >= Severity.HIGH),
        )
        report.fixtures.append(result)
        for rule_id in rule_ids:
            if expected == "safe":
                report.rule_fp[rule_id] += 1
            else:
                report.rule_tp[rule_id] += 1
    return report


def format_text(report: BenchmarkReport) -> str:
    lines = [
        "wtfguard heuristic benchmark",
        f"  total fixtures:   {len(report.fixtures)}",
        f"  safe:             {report.total_safe}",
        f"  malicious:        {report.total_malicious}",
        f"  true positives:   {report.true_positives}",
        f"  false positives:  {report.false_positives}   (rate {report.fp_rate:.1%})",
        f"  true negatives:   {report.true_negatives}",
        f"  false negatives:  {report.false_negatives}   (rate {report.fn_rate:.1%})",
        "",
        "rule activations (TP / FP):",
    ]
    rule_ids = sorted(set(report.rule_tp) | set(report.rule_fp))
    for rid in rule_ids:
        lines.append(f"  {rid:25} tp={report.rule_tp.get(rid, 0):2}  fp={report.rule_fp.get(rid, 0):2}")
    return "\n".join(lines)


def format_markdown(report: BenchmarkReport) -> str:
    lines = [
        "# wtfguard heuristic benchmark",
        "",
        f"- Total fixtures: **{len(report.fixtures)}**",
        f"- Safe: {report.total_safe}",
        f"- Malicious: {report.total_malicious}",
        f"- True positives: **{report.true_positives}**",
        f"- False positives: **{report.false_positives}** (rate **{report.fp_rate:.1%}**)",
        f"- True negatives: {report.true_negatives}",
        f"- False negatives: **{report.false_negatives}** (rate **{report.fn_rate:.1%}**)",
        "",
        "## Rule activations",
        "",
        "| Rule | TP | FP |",
        "|---|---:|---:|",
    ]
    rule_ids = sorted(set(report.rule_tp) | set(report.rule_fp))
    for rid in rule_ids:
        lines.append(f"| {rid} | {report.rule_tp.get(rid, 0)} | {report.rule_fp.get(rid, 0)} |")
    return "\n".join(lines)


def format_json(report: BenchmarkReport) -> str:
    payload: dict[str, Any] = {
        "totals": {
            "fixtures":        len(report.fixtures),
            "safe":            report.total_safe,
            "malicious":       report.total_malicious,
            "true_positives":  report.true_positives,
            "false_positives": report.false_positives,
            "true_negatives":  report.true_negatives,
            "false_negatives": report.false_negatives,
            "fp_rate":         report.fp_rate,
            "fn_rate":         report.fn_rate,
        },
        "rule_activations": {
            rid: {"tp": report.rule_tp.get(rid, 0), "fp": report.rule_fp.get(rid, 0)}
            for rid in sorted(set(report.rule_tp) | set(report.rule_fp))
        },
        "fixtures": [
            {
                "name":     f.name,
                "expected": f.expected,
                "severity": f.severity.label(),
                "kind":     f.kind,
                "rules":    list(f.rule_ids),
            }
            for f in report.fixtures
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
