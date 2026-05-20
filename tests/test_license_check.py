#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for license compliance checking."""

from __future__ import annotations

from wtfguard.license_check import (
    DEFAULT_ALLOWED_LICENSES,
    canonicalize,
    check,
    extract_licenses,
    is_allowed,
    split_license_string,
)
from wtfguard.models import Severity


def info(license_value: object = None, classifiers: list[str] | None = None) -> dict[str, object]:
    out: dict[str, object] = {}
    if license_value is not None:
        out["license"] = license_value
    if classifiers is not None:
        out["classifiers"] = classifiers
    return out


def test_extract_licenses_from_license_field() -> None:
    licenses = extract_licenses(info(license_value="MIT"))
    assert "MIT" in licenses


def test_extract_licenses_from_classifiers() -> None:
    licenses = extract_licenses(info(classifiers=[
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
    ]))
    assert "MIT License" in licenses
    assert "Apache Software License" in licenses


def test_extract_licenses_merges_sources() -> None:
    licenses = extract_licenses(info(
        license_value="BSD-3-Clause",
        classifiers=["License :: OSI Approved :: BSD License"],
    ))
    assert "BSD-3-Clause" in licenses
    assert "BSD License" in licenses


def test_extract_licenses_skips_non_license_classifiers() -> None:
    licenses = extract_licenses(info(classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
    ]))
    assert licenses == set()


def test_extract_licenses_handles_empty() -> None:
    assert extract_licenses({}) == set()
    assert extract_licenses(info(license_value="")) == set()


def test_split_license_string_or() -> None:
    assert "MIT" in split_license_string("MIT OR Apache-2.0")
    assert "Apache-2.0" in split_license_string("MIT OR Apache-2.0")


def test_split_license_string_separators() -> None:
    parts = split_license_string("MIT, BSD-3-Clause / ISC")
    assert set(parts) == {"MIT", "BSD-3-Clause", "ISC"}


def test_canonicalize_normalizes() -> None:
    # Spaces stripped, case-folded; dashes / dots preserved
    assert canonicalize("MIT License") == "mitlicense"
    assert canonicalize("Apache-2.0") == "apache-2.0"
    assert canonicalize("Apache 2.0") == "apache2.0"


def test_is_allowed_case_insensitive() -> None:
    assert is_allowed("mit", ["MIT"]) is True
    assert is_allowed("MIT", ["mit"]) is True


def test_check_mit_is_allowed() -> None:
    findings = check("demo", info(license_value="MIT"))
    assert findings == []


def test_check_unknown_license_emits_low() -> None:
    findings = check("demo", info())
    assert len(findings) == 1
    assert findings[0].rule_id == "LICENSE_UNKNOWN"
    assert findings[0].severity == Severity.LOW


def test_check_disallowed_license_emits_medium() -> None:
    findings = check("demo", info(license_value="AGPL-3.0"))
    assert len(findings) == 1
    assert findings[0].rule_id == "LICENSE_INCOMPATIBLE"
    assert findings[0].severity == Severity.MEDIUM


def test_check_custom_allowlist() -> None:
    findings = check("demo", info(license_value="Custom-Internal"), allowed=["Custom-Internal"])
    assert findings == []


def test_check_severity_override() -> None:
    findings = check(
        "demo",
        info(license_value="AGPL-3.0"),
        incompatible_severity=Severity.HIGH,
    )
    assert findings[0].severity == Severity.HIGH


def test_check_multi_license_one_allowed() -> None:
    # If ANY declared license is allowed, the package is allowed.
    findings = check("demo", info(license_value="MIT OR AGPL-3.0"))
    assert findings == []


def test_default_allowlist_covers_common_oss() -> None:
    assert is_allowed("MIT", DEFAULT_ALLOWED_LICENSES)
    assert is_allowed("Apache-2.0", DEFAULT_ALLOWED_LICENSES)
    assert is_allowed("BSD-3-Clause", DEFAULT_ALLOWED_LICENSES)
    assert not is_allowed("AGPL-3.0", DEFAULT_ALLOWED_LICENSES)
    assert not is_allowed("GPL-3.0", DEFAULT_ALLOWED_LICENSES)


def test_check_classifier_only_license() -> None:
    findings = check("demo", info(classifiers=["License :: OSI Approved :: MIT License"]))
    assert findings == []
