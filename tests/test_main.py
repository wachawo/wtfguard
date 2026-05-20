#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the package entry point (`python -m wtfguard`)."""

import subprocess
import sys


def test_module_executable_help() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wtfguard", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "wtfguard" in result.stdout.lower()


def test_module_executable_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wtfguard", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "wtfguard" in result.stdout
