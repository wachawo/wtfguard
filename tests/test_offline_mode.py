#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for analyzer offline mode."""

from __future__ import annotations

from wtfguard.analyzer import AnalysisOptions


def test_offline_disables_network_stages() -> None:
    opts = AnalysisOptions(offline=True)
    assert opts.use_llm is False
    assert opts.use_advisory is False
    assert opts.use_metadata is False
    # heuristics, typosquat, license_check stay enabled (typosquat is offline-only,
    # license_check uses cached metadata where available)
    assert opts.use_typosquat is True
    assert opts.use_license_check is True


def test_default_options_allow_network() -> None:
    opts = AnalysisOptions()
    assert opts.use_llm is True
    assert opts.use_advisory is True
    assert opts.use_metadata is True


def test_explicit_disables_survive_offline() -> None:
    # offline forces specific flags off but other explicit settings are honoured
    opts = AnalysisOptions(offline=True, use_typosquat=False)
    assert opts.use_typosquat is False
    assert opts.use_llm is False
