#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan a local directory of Python sources — pre-publish self-audit.

When you are about to release a package to PyPI, run wtfguard against
your own source tree first. This module wraps the heuristic engine with
no PyPI fetch, no advisory lookup, no LLM, no metadata — just regex /
AST / pyproject.toml checks. Fast and offline.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from wtfguard import heuristics
from wtfguard.models import Verdict

logger = logging.getLogger(__name__)

DEFAULT_PACKAGE_NAME = "<local>"


def scan_local_directory(
    root: Path,
    extra_rules: Iterable[Path] | None = None,
    package_name: str = DEFAULT_PACKAGE_NAME,
    package_version: str = "0.0.0",
) -> Verdict:
    """Run the heuristic engine on every relevant file under `root`."""
    rules = heuristics.load_rules(extra_paths=list(extra_rules) if extra_rules else None)
    findings = heuristics.scan_directory(root, rules)
    severity = heuristics.aggregate_severity(findings)
    confidence = 0.9 if findings else 1.0
    return Verdict(
        package=package_name,
        version=package_version,
        severity=severity,
        confidence=confidence,
        findings=findings,
    )
