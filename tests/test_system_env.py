#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for PEP 668 system-environment detection."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from wtfguard.system_env import (
    EnvironmentReport,
    externally_managed_marker,
    inspect,
    is_in_virtualenv,
)


def test_is_in_virtualenv_during_tests() -> None:
    # pytest runs inside our .venv, so we expect True. The flag flips on real
    # system Python, but this test asserts behaviour in the dev/test setup.
    assert is_in_virtualenv() is True


def test_externally_managed_marker_absent(monkeypatch) -> None:
    with patch("wtfguard.system_env.sysconfig.get_path", return_value="/nonexistent/path"):
        assert externally_managed_marker() is None


def test_externally_managed_marker_found(tmp_path: Path) -> None:
    fake_stdlib = tmp_path / "lib" / "python3.12"
    fake_stdlib.mkdir(parents=True)
    marker = tmp_path / "lib" / "EXTERNALLY-MANAGED"
    marker.write_text("[externally-managed]\n", encoding="utf-8")

    def fake_path(key: str) -> str:
        if key in {"stdlib", "purelib"}:
            return str(fake_stdlib)
        return ""

    with patch("wtfguard.system_env.sysconfig.get_path", side_effect=fake_path):
        assert externally_managed_marker() == marker


def test_inspect_returns_report() -> None:
    report = inspect()
    assert isinstance(report, EnvironmentReport)
    assert report.python_executable == sys.executable


def test_warning_text_externally_managed_no_venv() -> None:
    report = EnvironmentReport(
        is_virtualenv=False,
        is_externally_managed=True,
        marker_path=Path("/usr/lib/EXTERNALLY-MANAGED"),
        python_executable="/usr/bin/python3",
    )
    text = report.warning_text()
    assert text is not None
    assert "PEP 668" in text
    assert "virtualenv" in text


def test_warning_text_externally_managed_with_venv() -> None:
    # Inside a venv, the marker is irrelevant — pip can write here.
    report = EnvironmentReport(
        is_virtualenv=True,
        is_externally_managed=True,
        marker_path=Path("/usr/lib/EXTERNALLY-MANAGED"),
        python_executable="/venv/bin/python",
    )
    assert report.warning_text() is None


def test_warning_text_no_marker() -> None:
    report = EnvironmentReport(
        is_virtualenv=False,
        is_externally_managed=False,
        marker_path=None,
        python_executable="/usr/bin/python3",
    )
    assert report.warning_text() is None
