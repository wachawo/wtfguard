#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the self-test sanity checker."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from wtfguard.self_test import (
    CheckResult,
    SelfTestReport,
    check_heuristics_loadable,
    check_llm_backend,
    check_pep668,
    check_python_version,
    check_state_dir_writable,
    check_virtualenv,
    check_wtfguard_version,
    format_text,
    run_all,
)


def test_check_python_version_passes_on_311_plus() -> None:
    result = check_python_version()
    assert result.status == "pass"


def test_check_wtfguard_version_pass() -> None:
    result = check_wtfguard_version()
    assert result.status == "pass"
    assert result.name == "wtfguard_version"


def test_check_virtualenv_pass_inside_venv() -> None:
    with patch("wtfguard.self_test.system_env.is_in_virtualenv", return_value=True):
        result = check_virtualenv()
    assert result.status == "pass"


def test_check_virtualenv_warn_outside() -> None:
    with patch("wtfguard.self_test.system_env.is_in_virtualenv", return_value=False):
        result = check_virtualenv()
    assert result.status == "warn"


def test_check_pep668_no_marker() -> None:
    with patch("wtfguard.self_test.system_env.externally_managed_marker", return_value=None):
        result = check_pep668()
    assert result.status == "pass"


def test_check_pep668_inside_venv_with_marker() -> None:
    marker = Path("/usr/lib/EXTERNALLY-MANAGED")
    with patch("wtfguard.self_test.system_env.externally_managed_marker", return_value=marker), \
         patch("wtfguard.self_test.system_env.is_in_virtualenv", return_value=True):
        result = check_pep668()
    assert result.status == "pass"


def test_check_pep668_outside_venv_with_marker() -> None:
    marker = Path("/usr/lib/EXTERNALLY-MANAGED")
    with patch("wtfguard.self_test.system_env.externally_managed_marker", return_value=marker), \
         patch("wtfguard.self_test.system_env.is_in_virtualenv", return_value=False):
        result = check_pep668()
    assert result.status == "warn"


def test_check_heuristics_loadable_pass() -> None:
    result = check_heuristics_loadable()
    assert result.status == "pass"
    assert "rules loaded" in result.detail


def test_check_heuristics_loadable_failure() -> None:
    with patch("wtfguard.self_test.heuristics.load_rules", side_effect=RuntimeError("boom")):
        result = check_heuristics_loadable()
    assert result.status == "fail"


def test_check_heuristics_loadable_empty() -> None:
    with patch("wtfguard.self_test.heuristics.load_rules", return_value=[]):
        result = check_heuristics_loadable()
    assert result.status == "fail"


def test_check_state_dir_writable(tmp_path: Path) -> None:
    with patch("wtfguard.self_test.Path.home", return_value=tmp_path):
        result = check_state_dir_writable()
    assert result.status == "pass"


def test_check_llm_backend_no_backend() -> None:
    with patch("wtfguard.self_test.llm.active_backend", return_value=None):
        result = check_llm_backend()
    assert result.status == "warn"


def test_check_llm_backend_active() -> None:
    with patch("wtfguard.self_test.llm.active_backend", return_value="claude"):
        result = check_llm_backend()
    assert result.status == "pass"


def test_run_all_returns_report() -> None:
    report = run_all()
    assert isinstance(report, SelfTestReport)
    assert len(report.checks) >= 5


def test_report_counts() -> None:
    checks = [
        CheckResult("a", "pass", ""),
        CheckResult("b", "pass", ""),
        CheckResult("c", "warn", ""),
        CheckResult("d", "fail", ""),
    ]
    report = SelfTestReport(checks=checks)
    assert report.passes == 2
    assert report.warns == 1
    assert report.fails == 1


def test_format_text_includes_summary() -> None:
    report = run_all()
    out = format_text(report)
    assert "summary" in out
    assert "wtfguard self-test" in out


def test_to_dict_round_trip_keys() -> None:
    checks = [CheckResult("a", "pass", "x")]
    report = SelfTestReport(checks=checks)
    d = report.to_dict()
    assert d["passes"] == 1
    assert d["checks"][0]["status"] == "pass"
