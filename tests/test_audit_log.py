#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the append-only audit log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wtfguard.audit_log import (
    append_entry,
    is_enabled,
    log_batch,
    log_verdict,
    prune_older_than,
    read_entries,
    resolve_path,
)
from wtfguard.models import Finding, Severity, Verdict


def make_verdict() -> Verdict:
    finding = Finding(
        rule_id="NET_IN_SETUP",
        severity=Severity.HIGH,
        file="setup.py",
        line=10,
        snippet="urlopen('http://x')",
        description="Network call",
    )
    return Verdict(
        package="demo",
        version="1.0.0",
        severity=Severity.HIGH,
        confidence=0.85,
        findings=[finding],
        diff_hash="abc123",
        model="claude-haiku",
    )


def test_is_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WTFGUARD_AUDIT_DISABLED", raising=False)
    assert is_enabled() is True


def test_is_enabled_respects_disable_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WTFGUARD_AUDIT_DISABLED", "1")
    assert is_enabled() is False


def test_resolve_path_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WTFGUARD_AUDIT_LOG", str(tmp_path / "x.jsonl"))
    assert resolve_path() == tmp_path / "x.jsonl"


def test_append_entry_writes_jsonl(tmp_path: Path) -> None:
    target = tmp_path / "log.jsonl"
    append_entry({"event": "first"}, path=target)
    append_entry({"event": "second"}, path=target)
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "first"
    assert json.loads(lines[1])["event"] == "second"


def test_append_entry_disabled_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WTFGUARD_AUDIT_DISABLED", "true")
    target = tmp_path / "log.jsonl"
    append_entry({"event": "skipped"}, path=target)
    assert not target.exists()


def test_log_verdict_records_fields(tmp_path: Path) -> None:
    target = tmp_path / "log.jsonl"
    log_verdict(make_verdict(), command="scan", path=target)
    entries = read_entries(target)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["command"] == "scan"
    assert entry["package"] == "demo"
    assert entry["version"] == "1.0.0"
    assert entry["severity"] == "high"
    assert entry["findings_count"] == 1
    assert entry["rule_ids"] == ["NET_IN_SETUP"]
    assert entry["diff_hash"] == "abc123"
    assert entry["model"] == "claude-haiku"


def test_log_batch_one_line_per_verdict(tmp_path: Path) -> None:
    target = tmp_path / "log.jsonl"
    log_batch([make_verdict(), make_verdict()], command="scan-requirements", path=target)
    entries = read_entries(target)
    assert len(entries) == 2
    assert all(e["command"] == "scan-requirements" for e in entries)


def test_read_entries_missing_file_returns_empty(tmp_path: Path) -> None:
    assert read_entries(tmp_path / "absent.jsonl") == []


def test_read_entries_skips_malformed(tmp_path: Path) -> None:
    target = tmp_path / "log.jsonl"
    target.write_text(
        json.dumps({"good": 1}) + "\nthis is not json\n" + json.dumps({"good": 2}) + "\n",
        encoding="utf-8",
    )
    entries = read_entries(target)
    assert len(entries) == 2
    assert entries[0]["good"] == 1
    assert entries[1]["good"] == 2


def test_prune_removes_old_entries(tmp_path: Path) -> None:
    target = tmp_path / "log.jsonl"
    old = {"timestamp": "2000-01-01T00:00:00Z", "package": "ancient"}
    recent = {"timestamp": "2030-01-01T00:00:00Z", "package": "future"}
    target.write_text(json.dumps(old) + "\n" + json.dumps(recent) + "\n", encoding="utf-8")

    removed = prune_older_than(days=30, path=target)
    assert removed == 1

    entries = read_entries(target)
    assert len(entries) == 1
    assert entries[0]["package"] == "future"


def test_prune_missing_file(tmp_path: Path) -> None:
    assert prune_older_than(days=10, path=tmp_path / "absent") == 0


def test_log_lines_are_timestamped(tmp_path: Path) -> None:
    target = tmp_path / "log.jsonl"
    log_verdict(make_verdict(), path=target)
    entries = read_entries(target)
    assert "T" in entries[0]["timestamp"]


def test_append_entry_creates_parent_dir(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / "log.jsonl"
    append_entry({"event": "x"}, path=target)
    assert target.is_file()
