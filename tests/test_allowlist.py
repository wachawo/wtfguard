#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the allowlist loader."""

from pathlib import Path

import pytest

from wtfguard.allowlist import Allowlist, discover_path, load, normalize


def test_normalize_lowers_and_dashes() -> None:
    assert normalize("Foo_Bar") == "foo-bar"
    assert normalize("  Numpy  ") == "numpy"


def test_empty_allowlist_allows_nothing() -> None:
    a = Allowlist()
    assert a.allows("requests", "2.32.0") is False


def test_bare_name_matches_any_version() -> None:
    a = Allowlist(bare=frozenset({"requests"}))
    assert a.allows("requests", "2.32.0") is True
    assert a.allows("requests", None) is True
    assert a.allows("numpy", "1.0") is False


def test_pinned_matches_only_exact() -> None:
    a = Allowlist(pinned=frozenset({("requests", "2.32.0")}))
    assert a.allows("requests", "2.32.0") is True
    assert a.allows("requests", "2.31.0") is False
    assert a.allows("requests", None) is False


def test_glob_prefix() -> None:
    a = Allowlist(globs=("acme-*",))
    assert a.allows("acme-utils", "1.0") is True
    assert a.allows("acme-internal", None) is True
    assert a.allows("zoo", "1.0") is False


def test_load_missing_file_returns_empty(tmp_path: Path) -> None:
    a = load(tmp_path / "missing.txt")
    assert a.allows("anything", "1.0") is False


def test_load_parses_all_entry_types(tmp_path: Path) -> None:
    f = tmp_path / "ignore"
    f.write_text(
        "# comment\n"
        "\n"
        "requests\n"
        "numpy==1.26.0\n"
        "acme-*\n"
        "Foo_Bar  # inline comment\n",
        encoding="utf-8",
    )
    a = load(f)
    assert a.allows("requests", "2.32.0") is True
    assert a.allows("numpy", "1.26.0") is True
    assert a.allows("numpy", "1.27.0") is False
    assert a.allows("acme-utils", "x") is True
    assert a.allows("foo-bar", "x") is True
    assert a.allows("unknown", "x") is False


def test_load_ignores_unreadable(tmp_path: Path) -> None:
    f = tmp_path / "ignore"
    f.write_bytes(b"\xff\xfe\x00")
    a = load(f)
    # Either we tolerated the bytes or returned an empty allowlist — both fine
    assert isinstance(a, Allowlist)


def test_discover_path_prefers_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local = tmp_path / ".wtfguardignore"
    local.write_text("requests\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    discovered = discover_path()
    assert discovered == local


def test_discover_path_falls_back_to_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit.txt"
    explicit.write_text("requests\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WTFGUARD_ALLOWLIST", str(explicit))
    # Ensure no local file
    (tmp_path / ".wtfguardignore").unlink(missing_ok=True)
    discovered = discover_path()
    assert discovered == explicit


def test_discover_path_returns_none_when_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("WTFGUARD_ALLOWLIST", raising=False)
    monkeypatch.setattr("wtfguard.allowlist.DEFAULT_PATH", tmp_path / "absent.txt")
    assert discover_path() is None


def test_load_auto_discovers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".wtfguardignore").write_text("requests\n", encoding="utf-8")
    a = load()
    assert a.allows("requests", "2.32.0") is True
