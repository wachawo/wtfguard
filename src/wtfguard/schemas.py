#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSON Schema definitions for wtfguard's output formats.

Used by `wtfguard schema <name>` to print machine-readable contracts:
- `verdict`     — single Verdict JSON (from `scan --json`)
- `batch`       — batch scan output ({verdicts, allowlisted, worst})
- `sarif`       — link to OASIS SARIF 2.1.0 schema
- `cyclonedx`   — link to CycloneDX 1.5 schema

Embedding a hand-rolled JSON Schema avoids requiring jsonschema as a
runtime dep. Consumers can paste these into their CI validators.
"""

from __future__ import annotations

from typing import Any

VERDICT_SCHEMA: dict[str, Any] = {
    "$schema":     "https://json-schema.org/draft/2020-12/schema",
    "title":       "wtfguard verdict",
    "type":        "object",
    "required":    ["package", "version", "severity", "confidence", "findings", "scanned_at"],
    "properties": {
        "package":         {"type": "string"},
        "version":         {"type": "string"},
        "severity":        {"enum": ["clean", "low", "medium", "high", "critical"]},
        "confidence":      {"type": "number", "minimum": 0, "maximum": 1},
        "findings": {
            "type":  "array",
            "items": {
                "type":     "object",
                "required": ["rule_id", "severity", "file", "line", "snippet", "description"],
                "properties": {
                    "rule_id":     {"type": "string"},
                    "severity":    {"enum": ["clean", "low", "medium", "high", "critical"]},
                    "file":        {"type": "string"},
                    "line":        {"type": "integer", "minimum": 0},
                    "snippet":     {"type": "string"},
                    "description": {"type": "string"},
                },
            },
        },
        "diff_hash":       {"type": ["string", "null"]},
        "llm_explanation": {"type": ["string", "null"]},
        "model":           {"type": ["string", "null"]},
        "scanned_at":      {"type": "string", "format": "date-time"},
    },
}

BATCH_SCHEMA: dict[str, Any] = {
    "$schema":  "https://json-schema.org/draft/2020-12/schema",
    "title":    "wtfguard batch scan",
    "type":     "object",
    "required": ["verdicts", "worst"],
    "properties": {
        "verdicts":    {"type": "array", "items": VERDICT_SCHEMA},
        "allowlisted": {"type": "array", "items": {"type": "string"}},
        "worst":       {"enum": ["clean", "low", "medium", "high", "critical"]},
    },
}

EXTERNAL_SCHEMAS: dict[str, str] = {
    "sarif":     "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "cyclonedx": "https://cyclonedx.org/schema/bom-1.5.schema.json",
}

NAMES: tuple[str, ...] = ("verdict", "batch", "sarif", "cyclonedx")


def get_schema(name: str) -> dict[str, Any]:
    """Return the JSON Schema for a given output format name."""
    if name == "verdict":
        return VERDICT_SCHEMA
    if name == "batch":
        return BATCH_SCHEMA
    if name in EXTERNAL_SCHEMAS:
        return {
            "$ref": EXTERNAL_SCHEMAS[name],
            "comment": f"External schema — fetch from {EXTERNAL_SCHEMAS[name]}",
        }
    raise KeyError(f"unknown schema name: {name}")
