#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YAML policy file — severity overrides for rules and packages.

Enterprise teams need an escape hatch: "yes wtfguard, we know `acme-internal`
fires `NET_IN_SETUP` because we ship a private telemetry library, please
downgrade to LOW for that package only". This module loads a YAML policy
file and applies it to Verdict findings post-scan.

Schema:

    overrides:
      - rule: NET_IN_SETUP
        packages: [acme-internal]      # optional — applies to all when omitted
        severity: low                  # one of clean/low/medium/high/critical/ignore
      - rule: LICENSE_INCOMPATIBLE
        severity: ignore               # 'ignore' drops the finding entirely

Discovery: explicit --policy flag, then WTFGUARD_POLICY env, then
`./wtfguard-policy.yaml`.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from wtfguard.models import Finding, Severity, Verdict
from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)

ENV_VAR = "WTFGUARD_POLICY"
LOCAL_NAME = "wtfguard-policy.yaml"
IGNORE_SENTINEL = "ignore"


@dataclass(frozen=True)
class Override:
    rule:     str
    packages: frozenset[str]      # PEP 503-normalised; empty == applies to all
    severity: Severity | None     # None means "ignore this finding"

    def applies(self, package: str, rule_id: str) -> bool:
        if self.rule != rule_id:
            return False
        if not self.packages:
            return True
        return normalize_name(package) in self.packages


@dataclass(frozen=True)
class Policy:
    overrides: tuple[Override, ...] = field(default_factory=tuple)
    source:    Path | None = None

    def is_empty(self) -> bool:
        return not self.overrides


def discover_path(start_dir: Path | None = None) -> Path | None:
    env_value = os.getenv(ENV_VAR)
    if env_value:
        env_path = Path(env_value)
        if env_path.is_file():
            return env_path

    local = (start_dir or Path.cwd()) / LOCAL_NAME
    if local.is_file():
        return local

    return None


def load(path: Path | None = None) -> Policy:
    """Read a policy file. Returns an empty Policy if nothing is found or readable."""
    resolved = path if path is not None else discover_path()
    if resolved is None:
        return Policy()

    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning(f"Cannot parse policy {resolved}: {type(exc).__name__}: {exc}")
        return Policy()

    if not isinstance(raw, dict):
        logger.warning(f"Policy file {resolved} is not a mapping; ignoring")
        return Policy()

    overrides: list[Override] = []
    for entry in raw.get("overrides") or []:
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule")
        if not isinstance(rule, str) or not rule:
            continue
        severity = parse_severity(entry.get("severity"))
        packages = parse_packages(entry.get("packages"))
        overrides.append(Override(rule=rule, packages=packages, severity=severity))

    return Policy(overrides=tuple(overrides), source=resolved)


def parse_severity(value: Any) -> Severity | None:
    if not isinstance(value, str):
        return None
    if value.lower() == IGNORE_SENTINEL:
        return None
    try:
        return Severity.from_name(value)
    except KeyError:
        logger.warning(f"Policy: unknown severity {value!r}; treating as ignore")
        return None


def parse_packages(value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        return frozenset()
    return frozenset(
        normalize_name(p) for p in value if isinstance(p, str) and p.strip()
    )


def apply(verdict: Verdict, policy: Policy) -> Verdict:
    """Return a new Verdict with policy overrides applied to its findings.

    Findings whose policy maps to severity=None are dropped. Findings whose
    policy maps to a different severity are replaced with a copy carrying
    the new severity. The verdict's overall severity is recomputed from the
    surviving findings.
    """
    if policy.is_empty():
        return verdict

    surviving: list[Finding] = []
    for finding in verdict.findings:
        override = find_override(policy, verdict.package, finding.rule_id)
        if override is None:
            surviving.append(finding)
            continue
        if override.severity is None:
            continue  # dropped
        surviving.append(Finding(
            rule_id=finding.rule_id,
            severity=override.severity,
            file=finding.file,
            line=finding.line,
            snippet=finding.snippet,
            description=finding.description,
        ))

    new_severity = Severity(max((int(f.severity) for f in surviving), default=int(Severity.CLEAN)))
    return Verdict(
        package=verdict.package,
        version=verdict.version,
        severity=new_severity,
        confidence=verdict.confidence,
        findings=surviving,
        diff_hash=verdict.diff_hash,
        llm_explanation=verdict.llm_explanation,
        model=verdict.model,
        scanned_at=verdict.scanned_at,
    )


def find_override(policy: Policy, package: str, rule_id: str) -> Override | None:
    """Return the first override that matches, or None."""
    for override in policy.overrides:
        if override.applies(package, rule_id):
            return override
    return None
