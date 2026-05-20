#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the YAML policy loader and applier."""

from __future__ import annotations

from pathlib import Path

import pytest

from wtfguard.models import Finding, Severity, Verdict
from wtfguard.policy import (
    Override,
    Policy,
    apply,
    discover_path,
    find_override,
    load,
    parse_packages,
    parse_severity,
)


def make_verdict(severity: Severity = Severity.HIGH, findings: list[Finding] | None = None) -> Verdict:
    return Verdict(
        package="acme-internal",
        version="1.0.0",
        severity=severity,
        confidence=0.85,
        findings=findings or [
            Finding(
                rule_id="NET_IN_SETUP",
                severity=Severity.HIGH,
                file="setup.py",
                line=1,
                snippet="x",
                description="y",
            )
        ],
    )


def test_parse_severity_known_names() -> None:
    assert parse_severity("low") == Severity.LOW
    assert parse_severity("CRITICAL") == Severity.CRITICAL


def test_parse_severity_ignore() -> None:
    assert parse_severity("ignore") is None


def test_parse_severity_unknown_returns_none() -> None:
    assert parse_severity("nonsense") is None
    assert parse_severity(None) is None


def test_parse_packages_normalizes() -> None:
    assert parse_packages(["Acme_Internal", "Numpy"]) == frozenset({"acme-internal", "numpy"})


def test_parse_packages_invalid_input() -> None:
    assert parse_packages(None) == frozenset()
    assert parse_packages("string") == frozenset()
    assert parse_packages([1, "valid", None]) == frozenset({"valid"})


def test_override_applies_to_package() -> None:
    override = Override(rule="NET_IN_SETUP", packages=frozenset({"acme-internal"}), severity=Severity.LOW)
    assert override.applies("acme-internal", "NET_IN_SETUP") is True
    assert override.applies("Acme_Internal", "NET_IN_SETUP") is True
    assert override.applies("requests", "NET_IN_SETUP") is False


def test_override_applies_to_any_package_when_empty() -> None:
    override = Override(rule="NET_IN_SETUP", packages=frozenset(), severity=Severity.LOW)
    assert override.applies("anything", "NET_IN_SETUP") is True


def test_override_rule_mismatch() -> None:
    override = Override(rule="X", packages=frozenset(), severity=Severity.LOW)
    assert override.applies("any", "Y") is False


def test_load_empty_returns_empty_policy(tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text("overrides: []\n", encoding="utf-8")
    p = load(f)
    assert p.is_empty()


def test_load_full_policy(tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text(
        "overrides:\n"
        "  - rule: NET_IN_SETUP\n"
        "    packages: [acme-internal]\n"
        "    severity: low\n"
        "  - rule: LICENSE_INCOMPATIBLE\n"
        "    severity: ignore\n",
        encoding="utf-8",
    )
    p = load(f)
    assert len(p.overrides) == 2
    assert p.overrides[0].rule == "NET_IN_SETUP"
    assert p.overrides[0].severity == Severity.LOW
    assert p.overrides[1].severity is None  # ignore


def test_load_missing_returns_empty(tmp_path: Path) -> None:
    p = load(tmp_path / "absent.yaml")
    assert p.is_empty()


def test_load_malformed_yaml_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("this is not [[[ valid yaml", encoding="utf-8")
    p = load(f)
    assert p.is_empty()


def test_apply_downgrades_severity() -> None:
    override = Override(rule="NET_IN_SETUP", packages=frozenset({"acme-internal"}), severity=Severity.LOW)
    pol = Policy(overrides=(override,))
    verdict = make_verdict(severity=Severity.HIGH)

    applied = apply(verdict, pol)
    assert applied.severity == Severity.LOW
    assert applied.findings[0].severity == Severity.LOW


def test_apply_ignore_drops_finding() -> None:
    override = Override(rule="NET_IN_SETUP", packages=frozenset(), severity=None)
    pol = Policy(overrides=(override,))
    verdict = make_verdict(severity=Severity.HIGH)

    applied = apply(verdict, pol)
    assert applied.findings == []
    assert applied.severity == Severity.CLEAN


def test_apply_does_not_match_other_rules() -> None:
    override = Override(rule="OTHER_RULE", packages=frozenset(), severity=Severity.LOW)
    pol = Policy(overrides=(override,))
    verdict = make_verdict(severity=Severity.HIGH)

    applied = apply(verdict, pol)
    assert applied.findings[0].severity == Severity.HIGH  # unchanged


def test_apply_empty_policy_returns_input() -> None:
    pol = Policy()
    verdict = make_verdict(severity=Severity.HIGH)
    assert apply(verdict, pol) is verdict


def test_find_override_first_match_wins() -> None:
    a = Override(rule="R", packages=frozenset({"foo"}), severity=Severity.LOW)
    b = Override(rule="R", packages=frozenset(), severity=Severity.MEDIUM)
    pol = Policy(overrides=(a, b))
    assert find_override(pol, "foo", "R") == a
    assert find_override(pol, "bar", "R") == b


def test_discover_path_env_var(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = tmp_path / "explicit.yaml"
    f.write_text("overrides: []\n", encoding="utf-8")
    monkeypatch.setenv("WTFGUARD_POLICY", str(f))
    monkeypatch.chdir(tmp_path)
    assert discover_path() == f


def test_discover_path_local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("WTFGUARD_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    local = tmp_path / "wtfguard-policy.yaml"
    local.write_text("overrides: []\n", encoding="utf-8")
    assert discover_path() == local


def test_discover_path_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("WTFGUARD_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    assert discover_path() is None
