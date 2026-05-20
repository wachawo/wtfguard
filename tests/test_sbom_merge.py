#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the CycloneDX SBOM merger."""

from __future__ import annotations

import json
from pathlib import Path

from wtfguard.sbom_merge import component_score, load_bom, merge


def write_bom(path: Path, components: list[dict], vulnerabilities: list[dict] | None = None) -> Path:
    payload = {
        "bomFormat":       "CycloneDX",
        "specVersion":     "1.5",
        "version":         1,
        "components":      components,
        "vulnerabilities": vulnerabilities or [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_merge_two_bom_files(tmp_path: Path) -> None:
    a = write_bom(tmp_path / "a.json", [{"bom-ref": "pkg:pypi/requests@1.0", "name": "requests"}])
    b = write_bom(tmp_path / "b.json", [{"bom-ref": "pkg:pypi/numpy@1.0", "name": "numpy"}])
    merged = merge([a, b])

    refs = {c["bom-ref"] for c in merged["components"]}
    assert refs == {"pkg:pypi/requests@1.0", "pkg:pypi/numpy@1.0"}


def test_merge_dedupes_by_bom_ref(tmp_path: Path) -> None:
    a = write_bom(tmp_path / "a.json", [{"bom-ref": "pkg:pypi/x@1.0", "name": "x"}])
    b = write_bom(tmp_path / "b.json", [{"bom-ref": "pkg:pypi/x@1.0", "name": "x", "version": "1.0"}])
    merged = merge([a, b])
    assert len(merged["components"]) == 1


def test_merge_prefers_richer_component(tmp_path: Path) -> None:
    a = write_bom(tmp_path / "a.json", [{"bom-ref": "pkg:x@1", "name": "x"}])
    b = write_bom(tmp_path / "b.json", [{
        "bom-ref": "pkg:x@1", "name": "x", "version": "1.0",
        "purl": "pkg:pypi/x@1", "properties": [{"name": "a", "value": "b"}],
    }])
    merged = merge([a, b])
    chosen = merged["components"][0]
    assert "properties" in chosen


def test_merge_dedupes_vulnerabilities_by_id(tmp_path: Path) -> None:
    a = write_bom(tmp_path / "a.json", [], [{"id": "CVE-2024-1"}])
    b = write_bom(tmp_path / "b.json", [], [{"id": "CVE-2024-1"}, {"id": "CVE-2024-2"}])
    merged = merge([a, b])
    ids = {v["id"] for v in merged["vulnerabilities"]}
    assert ids == {"CVE-2024-1", "CVE-2024-2"}


def test_merge_skips_invalid_files(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    good = write_bom(tmp_path / "good.json", [{"bom-ref": "x", "name": "x"}])
    merged = merge([bad, good])
    assert len(merged["components"]) == 1


def test_merge_metadata_includes_tool_info() -> None:
    merged = merge([])
    tool = merged["metadata"]["tools"]["components"][0]
    assert tool["name"] == "wtfguard"


def test_load_bom_missing_file(tmp_path: Path) -> None:
    assert load_bom(tmp_path / "absent.json") is None


def test_load_bom_non_cyclonedx(tmp_path: Path) -> None:
    f = tmp_path / "other.json"
    f.write_text(json.dumps({"format": "spdx"}), encoding="utf-8")
    assert load_bom(f) is None


def test_load_bom_list_root(tmp_path: Path) -> None:
    f = tmp_path / "list.json"
    f.write_text("[]", encoding="utf-8")
    assert load_bom(f) is None


def test_component_score() -> None:
    assert component_score({"name": "x"}) == 0
    assert component_score({"name": "x", "purl": "y"}) == 1
    assert component_score({"name": "x", "purl": "y", "version": "1"}) == 2
    assert component_score({"name": "x", "properties": [{"a": 1}, {"b": 2}]}) == 2
