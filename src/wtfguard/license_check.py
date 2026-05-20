#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""License compliance — sixth detection axis.

Reads license metadata from PyPI JSON (`info.license` plus
`info.classifiers`) and matches it against an allowlist. Anything not on
the allowlist becomes a `LICENSE_INCOMPATIBLE` finding (medium by
default). Packages with no declared license at all become
`LICENSE_UNKNOWN` (low).

Config: `[license]` section in `wtfguard.toml`:

    [license]
    allowed = ["MIT", "Apache-2.0", "BSD-3-Clause"]
    severity = "high"        # override default for INCOMPATIBLE
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable

from wtfguard.models import Finding, Severity

logger = logging.getLogger(__name__)

# Default allowlist: permissive licenses safe for most commercial use.
# Copyleft licenses (GPL, AGPL) are explicitly NOT in the default list —
# they may be fine for some projects but require legal review.
DEFAULT_ALLOWED_LICENSES: frozenset[str] = frozenset({
    "MIT",
    "MIT License",
    "Apache-2.0",
    "Apache 2.0",
    "Apache License 2.0",
    "BSD",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD License",
    "ISC",
    "ISC License",
    "Python-2.0",
    "PSF",
    "Unlicense",
    "0BSD",
    "MPL-2.0",
    "Public Domain",
    "Zlib",
})

CLASSIFIER_PREFIX = "License :: "
CLASSIFIER_OSI_APPROVED = "OSI Approved :: "
LICENSE_TOKEN_RE = re.compile(r"[A-Za-z0-9.+-]+")


def extract_licenses(pypi_info: dict[str, object]) -> set[str]:
    """Pull every license-ish token from PyPI JSON `info`."""
    candidates: set[str] = set()

    raw_license = pypi_info.get("license")
    if isinstance(raw_license, str) and raw_license.strip():
        candidates.update(split_license_string(raw_license))

    classifiers = pypi_info.get("classifiers")
    if isinstance(classifiers, list):
        for c in classifiers:
            if not isinstance(c, str) or not c.startswith(CLASSIFIER_PREFIX):
                continue
            tail = c[len(CLASSIFIER_PREFIX) :].strip()
            tail = tail.removeprefix(CLASSIFIER_OSI_APPROVED).strip()
            if tail:
                candidates.update(split_license_string(tail))

    return {c.strip() for c in candidates if c.strip()}


def split_license_string(value: str) -> list[str]:
    """A license field may pack multiple SPDX-ish names separated by 'or'/','/'/'."""
    pieces = re.split(r"\s+(?:OR|AND|or|and)\s+|[,/]", value)
    return [p.strip() for p in pieces if p.strip()]


def is_allowed(license_name: str, allowed: Iterable[str]) -> bool:
    """Case-insensitive containment check, plus SPDX-style normalisation."""
    canonical = canonicalize(license_name)
    return any(canonicalize(a) == canonical for a in allowed)


def canonicalize(name: str) -> str:
    """Normalise a license name for comparison: lowercase, alphanumerics + dots only."""
    return "".join(ch.lower() for ch in name if ch.isalnum() or ch in {".", "-", "+"}).strip("-")


def check(
    package: str,
    pypi_info: dict[str, object],
    allowed: Iterable[str] | None = None,
    incompatible_severity: Severity = Severity.MEDIUM,
) -> list[Finding]:
    """Return license findings for the package's PyPI metadata."""
    allowed_set = frozenset(allowed) if allowed is not None else DEFAULT_ALLOWED_LICENSES
    licenses = extract_licenses(pypi_info)
    display = f"<license:{package}>"

    if not licenses:
        return [
            Finding(
                rule_id="LICENSE_UNKNOWN",
                severity=Severity.LOW,
                file=display,
                line=1,
                snippet="no license declared in PyPI metadata",
                description="Package does not declare a license — legal review recommended",
            )
        ]

    if any(is_allowed(lic, allowed_set) for lic in licenses):
        return []

    license_list = ", ".join(sorted(licenses))
    return [
        Finding(
            rule_id="LICENSE_INCOMPATIBLE",
            severity=incompatible_severity,
            file=display,
            line=1,
            snippet=license_list[:200],
            description=f"License(s) {license_list} not in allowlist — legal review required",
        )
    ]
