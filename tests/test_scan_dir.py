#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the local directory scanner."""

from __future__ import annotations

from pathlib import Path

from wtfguard.models import Severity
from wtfguard.scan_dir import scan_local_directory


def test_scan_clean_directory(safe_package: Path) -> None:
    verdict = scan_local_directory(safe_package, package_name="my-pkg", package_version="1.0")
    assert verdict.severity == Severity.CLEAN
    assert verdict.package == "my-pkg"
    assert verdict.version == "1.0"
    assert verdict.findings == []


def test_scan_malicious_directory_flagged_critical(malicious_package: Path) -> None:
    verdict = scan_local_directory(malicious_package)
    assert verdict.severity == Severity.CRITICAL
    assert verdict.findings
    rule_ids = {f.rule_id for f in verdict.findings}
    assert "CREDENTIAL_READ" in rule_ids


def test_scan_dir_with_custom_rules(tmp_path: Path, safe_package: Path) -> None:
    extra = tmp_path / "extra.yaml"
    extra.write_text(
        "rules:\n  - id: CUSTOM_HIT\n    severity: high\n"
        "    description: Always fires on this string\n    regex: 'safe_pkg'\n",
        encoding="utf-8",
    )
    verdict = scan_local_directory(safe_package, extra_rules=[extra])
    rule_ids = {f.rule_id for f in verdict.findings}
    assert "CUSTOM_HIT" in rule_ids


def test_scan_dir_default_package_name() -> None:
    from wtfguard.scan_dir import DEFAULT_PACKAGE_NAME

    verdict = scan_local_directory(Path("/nonexistent"))
    assert verdict.package == DEFAULT_PACKAGE_NAME
    assert verdict.findings == []


def test_scan_dir_returns_verdict_with_confidence(safe_package: Path) -> None:
    verdict = scan_local_directory(safe_package)
    assert verdict.confidence == 1.0
