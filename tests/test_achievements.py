#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for achievement unlock detection."""

from wtfguard.achievements import mark_unlocked, newly_unlocked
from wtfguard.state import State


def test_no_unlocks_when_below_thresholds() -> None:
    state = State(skips_total=5, reads_total=0)
    assert newly_unlocked(state) == []


def test_skip_10_unlocks_at_threshold() -> None:
    state = State(skips_total=10)
    unlocked = newly_unlocked(state)
    ids = {a.id for a in unlocked}
    assert "skip-10" in ids


def test_already_unlocked_not_repeated() -> None:
    state = State(skips_total=10, achievements=["skip-10"])
    unlocked = newly_unlocked(state)
    assert "skip-10" not in {a.id for a in unlocked}


def test_mark_unlocked_persists_to_state() -> None:
    state = State(skips_total=50)
    unlocked = newly_unlocked(state)
    mark_unlocked(state, unlocked)
    assert "skip-10" in state.achievements
    assert "skip-50" in state.achievements
    assert "skip-100" not in state.achievements


def test_skip_1000_secret_unlocks_at_threshold() -> None:
    state = State(skips_total=1000)
    unlocked = newly_unlocked(state)
    assert "skip-1000" in {a.id for a in unlocked}
