#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Merge multiple CycloneDX 1.5 SBOMs into one.

Monorepos that emit one CycloneDX file per subproject often want a
single merged SBOM for top-level reporting / Dependency-Track upload.
Components are deduplicated by `purl` (preferring entries with more
properties), vulnerabilities by `id`. Tool metadata lists every source
file.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wtfguard import __version__

logger = logging.getLogger(__name__)


def merge(paths: Iterable[Path]) -> dict[str, Any]:
    """Load every input file and return a merged CycloneDX dict."""
    raw_inputs = [load_bom(p) for p in paths]
    bom_inputs: list[dict[str, Any]] = [b for b in raw_inputs if b is not None]

    components_by_ref: dict[str, dict[str, Any]] = {}
    vulnerabilities_by_id: dict[str, dict[str, Any]] = {}

    for bom in bom_inputs:
        for component in bom.get("components") or []:
            if not isinstance(component, dict):
                continue
            ref = component.get("bom-ref") or component.get("purl") or component.get("name")
            if not isinstance(ref, str):
                continue
            existing = components_by_ref.get(ref)
            if existing is None or component_score(component) > component_score(existing):
                components_by_ref[ref] = component

        for vuln in bom.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id")
            if not isinstance(vuln_id, str):
                continue
            if vuln_id not in vulnerabilities_by_id:
                vulnerabilities_by_id[vuln_id] = vuln

    return {
        "bomFormat":     "CycloneDX",
        "specVersion":   "1.5",
        "serialNumber":  f"urn:uuid:{uuid.uuid4()}",
        "version":       1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {
                        "type":    "application",
                        "vendor":  "wachawo",
                        "name":    "wtfguard",
                        "version": __version__,
                        "properties": [
                            {"name": "wtfguard:source_files", "value": str(len(bom_inputs))},
                        ],
                    }
                ],
            },
        },
        "components":      list(components_by_ref.values()),
        "vulnerabilities": list(vulnerabilities_by_id.values()),
    }


def load_bom(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(f"Cannot read SBOM {path}: {type(exc).__name__}: {exc}")
        return None
    if not isinstance(data, dict):
        logger.warning(f"SBOM {path} is not a JSON object")
        return None
    if data.get("bomFormat") != "CycloneDX":
        logger.warning(f"SBOM {path}: bomFormat is not CycloneDX")
        return None
    return data


def component_score(component: dict[str, Any]) -> int:
    """Heuristic richness score — prefer components with more declared properties."""
    score = 0
    if "purl" in component:
        score += 1
    if "version" in component:
        score += 1
    if isinstance(component.get("properties"), list):
        score += len(component["properties"])
    return score
