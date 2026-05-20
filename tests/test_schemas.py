#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for JSON Schema definitions."""

from __future__ import annotations

import pytest

from wtfguard.schemas import (
    BATCH_SCHEMA,
    EXTERNAL_SCHEMAS,
    NAMES,
    VERDICT_SCHEMA,
    get_schema,
)


def test_names_include_known() -> None:
    assert "verdict" in NAMES
    assert "batch" in NAMES
    assert "sarif" in NAMES
    assert "cyclonedx" in NAMES


def test_verdict_schema_has_required_fields() -> None:
    required = VERDICT_SCHEMA["required"]
    for field in ("package", "version", "severity", "confidence", "findings"):
        assert field in required


def test_batch_schema_wraps_verdicts() -> None:
    properties = BATCH_SCHEMA["properties"]
    assert properties["verdicts"]["type"] == "array"
    assert properties["verdicts"]["items"] == VERDICT_SCHEMA


def test_get_schema_verdict() -> None:
    assert get_schema("verdict") == VERDICT_SCHEMA


def test_get_schema_batch() -> None:
    assert get_schema("batch") == BATCH_SCHEMA


def test_get_schema_external_returns_ref() -> None:
    schema = get_schema("sarif")
    assert "$ref" in schema
    assert schema["$ref"] == EXTERNAL_SCHEMAS["sarif"]


def test_get_schema_unknown_raises() -> None:
    with pytest.raises(KeyError):
        get_schema("totally-not-a-format")
