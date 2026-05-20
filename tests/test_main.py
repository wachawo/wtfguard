#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the package entry point (`python -m wtfguard`)."""

import os
import subprocess
import sys
from pathlib import Path


def child_env() -> dict[str, str]:
    """Subprocess env that points PYTHONPATH at src/ so `python -m wtfguard`
    works even when the package is not pip-installed."""
    env = os.environ.copy()
    src = Path(__file__).resolve().parents[1] / "src"
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src}{os.pathsep}{existing}" if existing else str(src)
    return env


def test_module_executable_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wtfguard", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        env=child_env(),
    )
    assert result.returncode == 0
    assert "wtfguard" in result.stdout.lower()


def test_module_executable_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wtfguard", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        env=child_env(),
    )
    assert result.returncode == 0
    assert "wtfguard" in result.stdout
