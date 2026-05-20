#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for baseline loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wtfguard.baseline import extract_specs, load_baseline, verdicts_to_payload
from wtfguard.models import Finding, Severity, Verdict


def test_load_baseline_round_trip(tmp_path: Path) -> None:
    payload = {"verdicts": [{"package": "foo", "version": "1.0", "severity": "low", "findings": []}]}
    p = tmp_path / "b.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    assert load_baseline(p) == payload


def test_load_baseline_rejects_non_object(tmp_path: Path) -> None:
    p = tmp_path / "list.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline(p)


def test_extract_specs_batch_shape() -> None:
    payload = {
        "verdicts": [
            {"package": "foo", "version": "1.0"},
            {"package": "bar", "version": "2.0"},
        ]
    }
    assert extract_specs(payload) == [("foo", "1.0"), ("bar", "2.0")]


def test_extract_specs_single_shape() -> None:
    payload = {"package": "demo", "version": "1.0.0"}
    assert extract_specs(payload) == [("demo", "1.0.0")]


def test_extract_specs_missing_version() -> None:
    payload = {"verdicts": [{"package": "foo"}]}
    assert extract_specs(payload) == [("foo", None)]


def test_extract_specs_empty_shape() -> None:
    assert extract_specs({}) == []
    assert extract_specs({"verdicts": []}) == []


def test_extract_specs_skips_malformed_entries() -> None:
    payload = {"verdicts": [
        {"package": "good", "version": "1.0"},
        "not a dict",
        {"version": "1.0"},  # missing package
        None,
    ]}
    assert extract_specs(payload) == [("good", "1.0")]


def test_verdicts_to_payload_shape() -> None:
    finding = Finding(
        rule_id="NET_IN_SETUP",
        severity=Severity.HIGH,
        file="setup.py",
        line=10,
        snippet="x",
        description="y",
    )
    verdict = Verdict(
        package="demo",
        version="1.0",
        severity=Severity.HIGH,
        confidence=0.8,
        findings=[finding],
    )
    payload = verdicts_to_payload([verdict], "high")
    assert payload["worst"] == "high"
    assert len(payload["verdicts"]) == 1
    assert payload["verdicts"][0]["package"] == "demo"
    assert payload["verdicts"][0]["findings"][0]["rule_id"] == "NET_IN_SETUP"


def test_verdicts_to_payload_empty() -> None:
    payload = verdicts_to_payload([], "clean")
    assert payload == {"verdicts": [], "allowlisted": [], "worst": "clean"}
