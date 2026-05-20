#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the file-watching loop."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from wtfguard.watch import MAX_POLL_INTERVAL, mtime_or_none, watch_file


def test_mtime_existing_file(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("hi", encoding="utf-8")
    assert mtime_or_none(f) is not None


def test_mtime_missing_file(tmp_path: Path) -> None:
    assert mtime_or_none(tmp_path / "absent") is None


def test_watch_fires_on_change(tmp_path: Path) -> None:
    import threading

    f = tmp_path / "x.txt"
    f.write_text("v1", encoding="utf-8")

    seen: list[Path] = []

    def bumper() -> None:
        # Wait for the watch loop to enter its first sleep, then bump mtime.
        time.sleep(0.05)
        new_mtime = f.stat().st_mtime + 100
        os.utime(f, (new_mtime, new_mtime))

    threading.Thread(target=bumper).start()

    fires = watch_file(f, on_change=lambda p: seen.append(p), interval=0.02, iterations=20)
    assert fires >= 1
    assert seen[0] == f


def test_watch_no_fires_when_unchanged(tmp_path: Path) -> None:
    f = tmp_path / "x.txt"
    f.write_text("static", encoding="utf-8")
    fires = watch_file(f, on_change=lambda p: None, interval=0.01, iterations=3)
    # mtime may have settled to the initial baseline value
    assert fires == 0


def test_watch_handles_callback_exception(tmp_path: Path) -> None:
    import threading

    f = tmp_path / "x.txt"
    f.write_text("hi", encoding="utf-8")

    def bumper() -> None:
        time.sleep(0.05)
        new_mtime = f.stat().st_mtime + 100
        os.utime(f, (new_mtime, new_mtime))

    threading.Thread(target=bumper).start()

    def boom(path: Path) -> None:
        raise RuntimeError("test")

    # Must not raise even though callback throws
    fires = watch_file(f, on_change=boom, interval=0.02, iterations=20)
    assert fires == 0  # exception is logged, fire counter not incremented


def test_watch_missing_target_skips(tmp_path: Path) -> None:
    fires = watch_file(tmp_path / "absent", on_change=lambda p: None, interval=0.01, iterations=2)
    assert fires == 0


def test_watch_rejects_zero_interval(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("hi", encoding="utf-8")
    with pytest.raises(ValueError):
        watch_file(f, on_change=lambda p: None, interval=0.0, iterations=1)


def test_watch_clamps_excessive_interval(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_text("hi", encoding="utf-8")
    # The interval gets clamped to MAX_POLL_INTERVAL internally. With
    # iterations=0 the loop body never runs, so this verifies only that
    # the function accepts an oversized interval without raising.
    fires = watch_file(f, on_change=lambda p: None, interval=MAX_POLL_INTERVAL + 100, iterations=0)
    assert fires == 0
