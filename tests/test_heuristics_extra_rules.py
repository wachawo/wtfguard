#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for custom-rules merging via extra_paths."""

from __future__ import annotations

from pathlib import Path

from wtfguard.heuristics import load_rules, read_rules_file
from wtfguard.models import Severity


def write_yaml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "extra.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_no_extra_paths_returns_bundled() -> None:
    bundled = load_rules()
    assert len(bundled) > 0
    ids = {r.id for r in bundled}
    assert "NET_IN_SETUP" in ids


def test_extra_rule_appended(tmp_path: Path) -> None:
    extra = write_yaml(tmp_path, """\
rules:
  - id: CUSTOM_NEW_RULE
    severity: high
    description: My custom rule
    file_scope: any
    regex: 'unique_marker_xyz'
""")
    merged = load_rules(extra_paths=[extra])
    ids = {r.id for r in merged}
    assert "CUSTOM_NEW_RULE" in ids
    assert "NET_IN_SETUP" in ids  # bundled still there


def test_extra_rule_overrides_builtin(tmp_path: Path) -> None:
    extra = write_yaml(tmp_path, """\
rules:
  - id: NET_IN_SETUP
    severity: low
    description: Downgraded for our team
    file_scope: install_script
    regex: 'urlopen'
""")
    merged = load_rules(extra_paths=[extra])
    by_id = {r.id: r for r in merged}
    assert by_id["NET_IN_SETUP"].severity == Severity.LOW
    assert by_id["NET_IN_SETUP"].description == "Downgraded for our team"


def test_missing_extra_path_warns_but_continues(tmp_path: Path) -> None:
    missing = tmp_path / "absent.yaml"
    rules = load_rules(extra_paths=[missing])
    assert len(rules) > 0  # bundled rules still loaded


def test_invalid_regex_in_extra_skipped(tmp_path: Path) -> None:
    extra = write_yaml(tmp_path, """\
rules:
  - id: BROKEN
    severity: low
    description: x
    regex: '([unclosed'
  - id: VALID_NEW
    severity: low
    description: ok
    regex: 'something'
""")
    rules = load_rules(extra_paths=[extra])
    ids = {r.id for r in rules}
    assert "BROKEN" not in ids
    assert "VALID_NEW" in ids


def test_read_rules_file_missing_returns_empty(tmp_path: Path) -> None:
    assert read_rules_file(tmp_path / "nope.yaml") == []


def test_read_rules_file_malformed_yaml(tmp_path: Path) -> None:
    f = write_yaml(tmp_path, "this is: not [[[ valid yaml")
    assert read_rules_file(f) == []


def test_multiple_extra_paths_merge_in_order(tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text(
        "rules:\n  - id: TEAM_RULE\n    severity: medium\n    description: from first\n    regex: 'a'\n",
        encoding="utf-8",
    )
    second.write_text(
        "rules:\n  - id: TEAM_RULE\n    severity: high\n    description: from second\n    regex: 'a'\n",
        encoding="utf-8",
    )
    rules = load_rules(extra_paths=[first, second])
    by_id = {r.id: r for r in rules}
    # Second overrides first
    assert by_id["TEAM_RULE"].severity == Severity.HIGH
    assert by_id["TEAM_RULE"].description == "from second"
