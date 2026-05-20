#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for verdict diff."""

from __future__ import annotations

import json
from pathlib import Path

from wtfguard.models import Severity
from wtfguard.verdict_diff import (
    VerdictDiff,
    diff,
    extract_findings,
    format_text,
    load_json,
)


def make_finding(rule_id: str = "NET_IN_SETUP", severity: str = "high",
                 file: str = "setup.py") -> dict:
    return {
        "rule_id":     rule_id,
        "severity":    severity,
        "file":        file,
        "line":        1,
        "snippet":     "x",
        "description": "y",
    }


def make_verdict(package: str = "demo", version: str = "1.0",
                 severity: str = "high", findings: list[dict] | None = None) -> dict:
    return {
        "package":   package,
        "version":   version,
        "severity":  severity,
        "findings":  findings or [],
    }


def batch_payload(verdicts: list[dict], worst: str = "clean") -> dict:
    return {"verdicts": verdicts, "allowlisted": [], "worst": worst}


def test_diff_identical_payloads_is_empty() -> None:
    payload = batch_payload([make_verdict()], worst="clean")
    result = diff(payload, payload)
    assert result.is_empty()


def test_diff_detects_added_finding() -> None:
    before = batch_payload([make_verdict(findings=[])], worst="clean")
    after = batch_payload([make_verdict(findings=[make_finding()])], worst="high")
    result = diff(before, after)
    assert len(result.added) == 1
    assert result.added[0].rule_id == "NET_IN_SETUP"
    assert result.worst_after == Severity.HIGH


def test_diff_detects_removed_finding() -> None:
    before = batch_payload([make_verdict(findings=[make_finding()])], worst="high")
    after = batch_payload([make_verdict(findings=[])], worst="clean")
    result = diff(before, after)
    assert len(result.removed) == 1


def test_diff_detects_severity_change() -> None:
    before = batch_payload([make_verdict(findings=[make_finding(severity="medium")])], worst="medium")
    after = batch_payload([make_verdict(findings=[make_finding(severity="critical")])], worst="critical")
    result = diff(before, after)
    assert len(result.severity_changed) == 1
    before_ref, after_ref = result.severity_changed[0]
    assert before_ref.severity == "medium"
    assert after_ref.severity == "critical"


def test_diff_single_scan_format() -> None:
    before = make_verdict(severity="clean", findings=[])
    after = make_verdict(severity="high", findings=[make_finding()])
    result = diff(before, after)
    assert len(result.added) == 1
    assert result.worst_after == Severity.HIGH


def test_diff_extract_handles_unknown_severity() -> None:
    payload = batch_payload([make_verdict()], worst="bogus-severity")
    _, worst = extract_findings(payload)
    assert worst == Severity.CLEAN


def test_diff_extract_skips_non_dict_findings() -> None:
    bad = {"package": "demo", "version": "1.0", "severity": "low",
           "findings": [None, 1, "x", make_finding()]}
    refs, _ = extract_findings(bad)
    assert len(refs) == 1


def test_load_json_round_trip(tmp_path: Path) -> None:
    payload = batch_payload([make_verdict()])
    f = tmp_path / "p.json"
    f.write_text(json.dumps(payload), encoding="utf-8")
    loaded = load_json(f)
    assert loaded == payload


def test_load_json_rejects_non_object(tmp_path: Path) -> None:
    import pytest
    f = tmp_path / "list.json"
    f.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        load_json(f)


def test_format_text_empty() -> None:
    empty = VerdictDiff(worst_before=Severity.CLEAN, worst_after=Severity.CLEAN)
    assert "no findings changed" in format_text(empty)


def test_format_text_with_additions() -> None:
    before = batch_payload([make_verdict(findings=[])], worst="clean")
    after = batch_payload([make_verdict(findings=[make_finding()])], worst="high")
    result = diff(before, after)
    output = format_text(result)
    assert "added" in output
    assert "NET_IN_SETUP" in output


def test_format_text_with_severity_change() -> None:
    before = batch_payload([make_verdict(findings=[make_finding(severity="low")])], worst="low")
    after = batch_payload([make_verdict(findings=[make_finding(severity="critical")])], worst="critical")
    result = diff(before, after)
    output = format_text(result)
    assert "severity changed" in output
    assert "low -> critical" in output


def test_diff_independent_keys_per_package() -> None:
    before = batch_payload([
        make_verdict(package="a", findings=[make_finding("R1")]),
    ], worst="high")
    after = batch_payload([
        make_verdict(package="a", findings=[make_finding("R1")]),
        make_verdict(package="b", findings=[make_finding("R1")]),
    ], worst="high")
    result = diff(before, after)
    assert len(result.added) == 1
    assert result.added[0].package == "b"
