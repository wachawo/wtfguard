#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for typosquat.write_popular."""

from __future__ import annotations

from pathlib import Path

from wtfguard.typosquat import load_popular, write_popular


def test_write_popular_basic(tmp_path: Path) -> None:
    f = tmp_path / "popular.txt"
    count = write_popular(["requests", "numpy", "pandas"], f)
    assert count == 3
    text = f.read_text(encoding="utf-8")
    assert "requests" in text
    assert "numpy" in text
    assert text.startswith("# Curated")


def test_write_popular_normalizes_and_dedupes(tmp_path: Path) -> None:
    f = tmp_path / "popular.txt"
    count = write_popular(["Requests", "REQUESTS", "Foo_Bar", "foo-bar", "  numpy  "], f)
    assert count == 3
    text = f.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert "requests" in lines
    assert "foo-bar" in lines
    assert "numpy" in lines


def test_write_popular_skips_non_strings(tmp_path: Path) -> None:
    f = tmp_path / "popular.txt"
    count = write_popular(["requests", None, 12345, "numpy"], f)  # type: ignore[list-item]
    assert count == 2


def test_write_then_load_round_trip(tmp_path: Path) -> None:
    f = tmp_path / "popular.txt"
    write_popular(["requests", "numpy"], f)
    loaded = load_popular(f)
    assert "requests" in loaded
    assert "numpy" in loaded


def test_write_popular_creates_parent_dir(tmp_path: Path) -> None:
    f = tmp_path / "nested" / "dir" / "popular.txt"
    count = write_popular(["foo"], f)
    assert count == 1
    assert f.is_file()


def test_write_popular_output_sorted(tmp_path: Path) -> None:
    f = tmp_path / "popular.txt"
    write_popular(["zoo", "alpha", "middle"], f)
    text = f.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert lines == sorted(lines)
