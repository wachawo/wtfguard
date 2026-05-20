#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for user state persistence."""

from pathlib import Path

from wtfguard.state import State, load_state, save_state


def test_load_missing_returns_defaults(tmp_path: Path) -> None:
    state = load_state(tmp_path / "missing.json")
    assert state.skips_total == 0
    assert state.scans_total == 0
    assert state.achievements == []
    assert state.talkative is False


def test_save_and_reload_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    original = State(skips_total=42, reads_total=7, scans_total=15, achievements=["skip-10"], talkative=True)
    save_state(original, path)
    loaded = load_state(path)
    assert loaded.skips_total == 42
    assert loaded.reads_total == 7
    assert loaded.scans_total == 15
    assert loaded.achievements == ["skip-10"]
    assert loaded.talkative is True


def test_load_corrupt_returns_defaults(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("this is not json", encoding="utf-8")
    state = load_state(path)
    assert state.skips_total == 0
