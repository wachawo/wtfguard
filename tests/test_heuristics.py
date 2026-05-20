#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the regex/AST heuristics engine."""

from pathlib import Path

from wtfguard.heuristics import (
    aggregate_severity,
    load_rules,
    scan_ast_setup_py,
    scan_directory,
    scan_text,
)
from wtfguard.models import Severity


def test_load_rules_returns_nonempty() -> None:
    rules = load_rules()
    assert len(rules) >= 6
    ids = {r.id for r in rules}
    assert "NET_IN_SETUP" in ids
    assert "EXEC_OBFUSCATED" in ids
    assert "CREDENTIAL_READ" in ids


def test_safe_package_is_clean(safe_package: Path) -> None:
    rules = load_rules()
    findings = scan_directory(safe_package, rules)
    high_or_above = [f for f in findings if f.severity >= Severity.HIGH]
    assert high_or_above == [], f"safe package produced high findings: {high_or_above}"


def test_malicious_package_triggers_critical(malicious_package: Path) -> None:
    rules = load_rules()
    findings = scan_directory(malicious_package, rules)
    severity = aggregate_severity(findings)
    assert severity == Severity.CRITICAL
    rule_ids = {f.rule_id for f in findings}
    assert "CREDENTIAL_READ" in rule_ids
    assert "EXEC_OBFUSCATED" in rule_ids
    assert "BASE64_BLOB" in rule_ids


def test_install_script_scope_filters_correctly() -> None:
    rules = load_rules()
    net_rule = next(r for r in rules if r.id == "NET_IN_SETUP")
    content = "import urllib\nurllib.urlopen('http://x')\n"

    setup_findings = scan_text(Path("setup.py"), content, [net_rule])
    assert len(setup_findings) == 1
    assert setup_findings[0].file == "setup.py"

    lib_findings = scan_text(Path("mylib/util.py"), content, [net_rule])
    assert lib_findings == []


def test_ast_detects_cmdclass_subprocess(cmdclass_package: Path) -> None:
    setup_py = cmdclass_package / "setup.py"
    findings = scan_ast_setup_py(Path("setup.py"), setup_py.read_text(encoding="utf-8"))
    rule_ids = {f.rule_id for f in findings}
    assert "CUSTOM_CMDCLASS" in rule_ids
    assert "CMDCLASS_SUBPROCESS" in rule_ids


def test_aggregate_severity_empty() -> None:
    assert aggregate_severity([]) == Severity.CLEAN


def test_aggregate_severity_picks_max(malicious_package: Path) -> None:
    rules = load_rules()
    findings = scan_directory(malicious_package, rules)
    assert aggregate_severity(findings) == Severity.CRITICAL
