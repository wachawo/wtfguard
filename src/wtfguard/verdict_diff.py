#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare two JSON verdict outputs and report what changed.

Input shape — either:
- single-package output from `wtfguard scan --json`, or
- batch output from `wtfguard scan-requirements --json` / `scan-installed --json`
  which has shape `{verdicts: [...], allowlisted: [...], worst: ...}`.

The output highlights what a security reviewer cares about during an
upgrade: findings that appeared, findings that disappeared, severity
changes per package, and the worst-severity delta.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wtfguard.models import Severity


@dataclass
class FindingRef:
    package:  str
    version:  str
    rule_id:  str
    severity: str
    file:     str
    line:     int

    def key(self) -> tuple[str, str, str]:
        return (self.package, self.rule_id, self.file)

    def display(self) -> str:
        return f"{self.package}={self.version} :: {self.severity:8} {self.rule_id:24} {self.file}:{self.line}"


@dataclass
class VerdictDiff:
    added:             list[FindingRef] = field(default_factory=list)
    removed:           list[FindingRef] = field(default_factory=list)
    severity_changed:  list[tuple[FindingRef, FindingRef]] = field(default_factory=list)
    worst_before:      Severity = Severity.CLEAN
    worst_after:       Severity = Severity.CLEAN

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.severity_changed)


def load_json(path: Path) -> dict[str, Any]:
    """Parse a JSON file. Raises ValueError on malformed input."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data
    raise ValueError(f"{path}: expected a JSON object, got {type(data).__name__}")


def extract_findings(payload: dict[str, Any]) -> tuple[list[FindingRef], Severity]:
    """Flatten findings from either single-scan or batch JSON shape."""
    verdicts = payload.get("verdicts")
    if isinstance(verdicts, list):
        return collect_batch(verdicts, payload.get("worst", "clean"))
    return collect_single(payload)


def collect_batch(verdicts: list[dict[str, Any]], worst_raw: str) -> tuple[list[FindingRef], Severity]:
    refs: list[FindingRef] = []
    for verdict in verdicts:
        refs.extend(refs_for_verdict(verdict))
    try:
        worst = Severity.from_name(str(worst_raw))
    except KeyError:
        worst = Severity.CLEAN
    return refs, worst


def collect_single(payload: dict[str, Any]) -> tuple[list[FindingRef], Severity]:
    refs = refs_for_verdict(payload)
    try:
        worst = Severity.from_name(str(payload.get("severity", "clean")))
    except KeyError:
        worst = Severity.CLEAN
    return refs, worst


def refs_for_verdict(verdict: dict[str, Any]) -> list[FindingRef]:
    package = str(verdict.get("package", ""))
    version = str(verdict.get("version", ""))
    findings = verdict.get("findings") or []
    out: list[FindingRef] = []
    if not isinstance(findings, list):
        return out
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        out.append(
            FindingRef(
                package=package,
                version=version,
                rule_id=str(finding.get("rule_id", "?")),
                severity=str(finding.get("severity", "low")),
                file=str(finding.get("file", "")),
                line=int(finding.get("line", 0) or 0),
            )
        )
    return out


def diff(before_payload: dict[str, Any], after_payload: dict[str, Any]) -> VerdictDiff:
    """Compute the symmetric difference between two verdict payloads."""
    before_refs, worst_before = extract_findings(before_payload)
    after_refs, worst_after = extract_findings(after_payload)

    before_index = {r.key(): r for r in before_refs}
    after_index = {r.key(): r for r in after_refs}

    added = [after_index[k] for k in after_index.keys() - before_index.keys()]
    removed = [before_index[k] for k in before_index.keys() - after_index.keys()]

    severity_changed: list[tuple[FindingRef, FindingRef]] = []
    for k in before_index.keys() & after_index.keys():
        a = before_index[k]
        b = after_index[k]
        if a.severity != b.severity:
            severity_changed.append((a, b))

    added.sort(key=lambda r: (r.package, r.rule_id))
    removed.sort(key=lambda r: (r.package, r.rule_id))
    severity_changed.sort(key=lambda pair: (pair[0].package, pair[0].rule_id))

    return VerdictDiff(
        added=added,
        removed=removed,
        severity_changed=severity_changed,
        worst_before=worst_before,
        worst_after=worst_after,
    )


def format_text(d: VerdictDiff) -> str:
    if d.is_empty():
        return (
            f"no findings changed (worst: {d.worst_before.label()} -> {d.worst_after.label()})"
            if d.worst_before == d.worst_after
            else f"worst severity {d.worst_before.label()} -> {d.worst_after.label()} but per-finding parity"
        )

    lines = [f"worst severity: {d.worst_before.label()} -> {d.worst_after.label()}", ""]

    if d.added:
        lines.append(f"+ {len(d.added)} added")
        for ref in d.added:
            lines.append(f"  + {ref.display()}")
        lines.append("")

    if d.removed:
        lines.append(f"- {len(d.removed)} removed")
        for ref in d.removed:
            lines.append(f"  - {ref.display()}")
        lines.append("")

    if d.severity_changed:
        lines.append(f"~ {len(d.severity_changed)} severity changed")
        for before, after in d.severity_changed:
            lines.append(
                f"  ~ {before.package} {before.rule_id}: {before.severity} -> {after.severity}"
            )

    return "\n".join(lines).rstrip()
