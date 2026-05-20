#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for CycloneDX 1.5 SBOM generation."""

from __future__ import annotations

import json

from wtfguard.cyclonedx import (
    CYCLONEDX_VERSION,
    build_bom,
    component_for,
    package_url,
    parse_advisory_id,
    vulnerabilities_for,
)
from wtfguard.models import Finding, Severity, Verdict


def make_finding(rule: str = "NET_IN_SETUP", severity: Severity = Severity.HIGH,
                 snippet: str = "urlopen('http://x')") -> Finding:
    return Finding(
        rule_id=rule,
        severity=severity,
        file="setup.py",
        line=10,
        snippet=snippet,
        description="Network call in install-script file",
    )


def advisory_finding() -> Finding:
    return Finding(
        rule_id="KNOWN_ADVISORY",
        severity=Severity.CRITICAL,
        file="<advisory>",
        line=1,
        snippet="GHSA-xxxx-yyyy-zzzz (CVSS 9.8) aka CVE-2024-1234",
        description="Remote code execution in foo",
    )


def make_verdict(severity: Severity = Severity.HIGH, findings: list[Finding] | None = None) -> Verdict:
    return Verdict(
        package="demo",
        version="1.0.0",
        severity=severity,
        confidence=0.85,
        findings=findings or [make_finding()],
    )


def test_bom_structure_minimal() -> None:
    bom = build_bom([])
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == CYCLONEDX_VERSION
    assert bom["version"] == 1
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["components"] == []
    assert bom["vulnerabilities"] == []


def test_bom_metadata_includes_tool() -> None:
    bom = build_bom([])
    tool = bom["metadata"]["tools"]["components"][0]
    assert tool["vendor"] == "wachawo"
    assert tool["name"] == "wtfguard"


def test_component_per_verdict() -> None:
    bom = build_bom([make_verdict()])
    assert len(bom["components"]) == 1
    comp = bom["components"][0]
    assert comp["type"] == "library"
    assert comp["name"] == "demo"
    assert comp["version"] == "1.0.0"
    assert comp["purl"] == "pkg:pypi/demo@1.0.0"


def test_package_url_normalizes_name() -> None:
    assert package_url("Foo_Bar", "1.0") == "pkg:pypi/foo-bar@1.0"


def test_component_properties_carry_findings() -> None:
    verdict = make_verdict(findings=[make_finding("NET_IN_SETUP", Severity.HIGH),
                                     make_finding("EXEC_OBFUSCATED", Severity.CRITICAL)])
    comp = component_for(verdict)
    prop_names = {p["name"] for p in comp["properties"]}
    assert "wtfguard:severity" in prop_names
    assert "wtfguard:confidence" in prop_names
    assert "wtfguard:finding:NET_IN_SETUP" in prop_names
    assert "wtfguard:finding:EXEC_OBFUSCATED" in prop_names


def test_advisory_findings_become_vulnerabilities() -> None:
    verdict = make_verdict(severity=Severity.CRITICAL, findings=[advisory_finding()])
    vulns = list(vulnerabilities_for([verdict]))
    assert len(vulns) == 1
    v = vulns[0]
    assert v["id"] == "GHSA-xxxx-yyyy-zzzz"
    assert v["source"]["name"] == "OSV"
    assert v["ratings"][0]["severity"] == "critical"
    assert v["affects"][0]["ref"] == "pkg:pypi/demo@1.0.0"


def test_advisory_finding_not_in_component_properties() -> None:
    verdict = make_verdict(severity=Severity.CRITICAL,
                           findings=[advisory_finding(), make_finding("NET_IN_SETUP")])
    comp = component_for(verdict)
    prop_names = {p["name"] for p in comp["properties"]}
    assert "wtfguard:finding:KNOWN_ADVISORY" not in prop_names
    assert "wtfguard:finding:NET_IN_SETUP" in prop_names


def test_parse_advisory_id_ghsa() -> None:
    assert parse_advisory_id("GHSA-xxxx-yyyy-zzzz aka CVE-1") == "GHSA-xxxx-yyyy-zzzz"


def test_parse_advisory_id_cve_only() -> None:
    assert parse_advisory_id("CVE-2024-1234 (CVSS 8.0)") == "CVE-2024-1234"


def test_parse_advisory_id_pysec() -> None:
    assert parse_advisory_id("PYSEC-2024-0001") == "PYSEC-2024-0001"


def test_parse_advisory_id_none() -> None:
    assert parse_advisory_id("no id here") is None


def test_bom_is_valid_json() -> None:
    bom = build_bom([make_verdict()])
    serialized = json.dumps(bom)
    assert json.loads(serialized) == bom


def test_component_includes_llm_metadata() -> None:
    verdict = Verdict(
        package="demo",
        version="1.0",
        severity=Severity.HIGH,
        confidence=0.8,
        findings=[make_finding()],
        llm_explanation="malicious-looking install script",
        model="claude-haiku",
    )
    comp = component_for(verdict)
    prop_dict = {p["name"]: p["value"] for p in comp["properties"]}
    assert prop_dict["wtfguard:llm_model"] == "claude-haiku"
    assert "malicious" in prop_dict["wtfguard:llm_explanation"]


def test_component_diff_hash_property() -> None:
    verdict = Verdict(package="demo", version="1.0", severity=Severity.LOW,
                      confidence=1.0, findings=[], diff_hash="abc123")
    comp = component_for(verdict)
    if "properties" in comp:
        prop_dict = {p["name"]: p["value"] for p in comp["properties"]}
        assert prop_dict.get("wtfguard:diff_hash") == "abc123"
