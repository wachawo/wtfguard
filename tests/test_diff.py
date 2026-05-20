#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for tree diff and diff hashing."""

from pathlib import Path

from wtfguard.diff import diff_hash, file_diff, meaningful_diffs, tree_diff


def test_identical_trees_have_no_meaningful_diffs(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")
    (b / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")

    diffs = tree_diff(a, b)
    assert meaningful_diffs(diffs) == []


def test_added_file_is_meaningful(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (b / "evil.py").write_text("import os\n", encoding="utf-8")

    diffs = tree_diff(a, b)
    meaningful = meaningful_diffs(diffs)
    assert len(meaningful) == 1
    assert meaningful[0].status == "added"
    assert meaningful[0].path == "evil.py"


def test_diff_hash_is_stable(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "setup.py").write_text("v1\n", encoding="utf-8")
    (b / "setup.py").write_text("v2\n", encoding="utf-8")

    h1 = diff_hash(tree_diff(a, b))
    h2 = diff_hash(tree_diff(a, b))
    assert h1 == h2
    assert len(h1) == 64


def test_diff_hash_changes_when_content_changes(tmp_path: Path) -> None:
    a = tmp_path / "a"
    a.mkdir()
    b = tmp_path / "b"
    b.mkdir()
    c = tmp_path / "c"
    c.mkdir()
    (a / "setup.py").write_text("v1\n", encoding="utf-8")
    (b / "setup.py").write_text("v2\n", encoding="utf-8")
    (c / "setup.py").write_text("v3\n", encoding="utf-8")

    h_ab = diff_hash(tree_diff(a, b))
    h_ac = diff_hash(tree_diff(a, c))
    assert h_ab != h_ac


def test_file_diff_status_modified(tmp_path: Path) -> None:
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("line1\nline2\n", encoding="utf-8")
    new.write_text("line1\nLINE2\n", encoding="utf-8")

    d = file_diff("x.txt", old, new)
    assert d.status == "modified"
    assert "-line2" in d.body
    assert "+LINE2" in d.body
