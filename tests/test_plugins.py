#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for entry-point plugin discovery."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wtfguard.plugins import discover_rule_paths, resolve_target


def fake_ep(name: str, target: object) -> SimpleNamespace:
    """Build a minimal EntryPoint stand-in."""
    return SimpleNamespace(name=name, load=lambda: target)


def make_yaml_rules(tmp_path: Path, contents: str = "rules: []\n") -> Path:
    f = tmp_path / "rules.yaml"
    f.write_text(contents, encoding="utf-8")
    return f


def test_no_entry_points_returns_empty() -> None:
    with patch("wtfguard.plugins._entry_points_for_group", return_value=[]):
        assert discover_rule_paths() == []


def test_entry_point_returning_path(tmp_path: Path) -> None:
    rules = make_yaml_rules(tmp_path)
    with patch("wtfguard.plugins._entry_points_for_group", return_value=[fake_ep("p", rules)]):
        result = discover_rule_paths()
    assert result == [rules]


def test_entry_point_returning_string(tmp_path: Path) -> None:
    rules = make_yaml_rules(tmp_path)
    with patch("wtfguard.plugins._entry_points_for_group", return_value=[fake_ep("p", str(rules))]):
        result = discover_rule_paths()
    assert result == [rules]


def test_entry_point_returning_callable(tmp_path: Path) -> None:
    rules = make_yaml_rules(tmp_path)

    def get_rules() -> Path:
        return rules

    with patch("wtfguard.plugins._entry_points_for_group", return_value=[fake_ep("p", get_rules)]):
        result = discover_rule_paths()
    assert result == [rules]


def test_entry_point_pointing_at_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "absent.yaml"
    with patch("wtfguard.plugins._entry_points_for_group", return_value=[fake_ep("p", missing)]):
        result = discover_rule_paths()
    assert result == []


def test_entry_point_load_failure_is_skipped() -> None:
    broken = SimpleNamespace(name="broken", load=lambda: (_ for _ in ()).throw(RuntimeError("nope")))
    with patch("wtfguard.plugins._entry_points_for_group", return_value=[broken]):
        result = discover_rule_paths()
    assert result == []


def test_unsupported_target_type_skipped() -> None:
    bad = fake_ep("bad", 12345)  # int is not a path / callable
    with patch("wtfguard.plugins._entry_points_for_group", return_value=[bad]):
        result = discover_rule_paths()
    assert result == []


def test_resolve_target_callable_raises_returns_none() -> None:
    def crashy() -> Path:
        raise RuntimeError("boom")

    assert resolve_target("p", crashy) is None


def test_resolve_target_path_missing_returns_none(tmp_path: Path) -> None:
    assert resolve_target("p", tmp_path / "absent.yaml") is None


def test_multiple_entry_points_merged(tmp_path: Path) -> None:
    a = make_yaml_rules(tmp_path / "a.yaml") if False else tmp_path / "a.yaml"
    a.write_text("rules: []\n", encoding="utf-8")
    b = tmp_path / "b.yaml"
    b.write_text("rules: []\n", encoding="utf-8")

    eps = [fake_ep("a", a), fake_ep("b", b)]
    with patch("wtfguard.plugins._entry_points_for_group", return_value=eps):
        result = discover_rule_paths()
    assert set(result) == {a, b}


def test_load_rules_includes_plugin_rules(tmp_path: Path) -> None:
    from wtfguard.heuristics import load_rules

    plugin_yaml = tmp_path / "plug.yaml"
    plugin_yaml.write_text(
        "rules:\n  - id: PLUGIN_NEW\n    severity: high\n"
        "    description: from plugin\n    regex: 'marker_xyz'\n",
        encoding="utf-8",
    )
    with patch("wtfguard.plugins.discover_rule_paths", return_value=[plugin_yaml]):
        rules = load_rules()
    ids = {r.id for r in rules}
    assert "PLUGIN_NEW" in ids


def test_load_rules_can_skip_plugins(tmp_path: Path) -> None:
    from wtfguard.heuristics import load_rules

    plugin_yaml = tmp_path / "plug.yaml"
    plugin_yaml.write_text(
        "rules:\n  - id: PLUGIN_NEW\n    severity: high\n"
        "    description: x\n    regex: 'y'\n",
        encoding="utf-8",
    )
    with patch("wtfguard.plugins.discover_rule_paths", return_value=[plugin_yaml]):
        rules = load_rules(include_plugins=False)
    ids = {r.id for r in rules}
    assert "PLUGIN_NEW" not in ids
