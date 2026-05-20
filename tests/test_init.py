#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the top-level package surface."""

import wtfguard
from wtfguard import Finding, Severity, Verdict


def test_version_is_set() -> None:
    assert isinstance(wtfguard.__version__, str)
    assert len(wtfguard.__version__) >= 5


def test_public_surface_reexports() -> None:
    assert Severity is wtfguard.Severity
    assert Finding is wtfguard.Finding
    assert Verdict is wtfguard.Verdict


def test_all_lists_public_names() -> None:
    assert set(wtfguard.__all__) >= {"Finding", "Severity", "Verdict", "__version__"}
