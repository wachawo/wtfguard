#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""File-watching loop for `wtfguard watch <file>`.

Polls file mtime — no inotify / kqueue dependency. Cheap and portable.
On every change, fires a user-supplied callback with the file path.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL = 1.0
MAX_POLL_INTERVAL = 30.0


def mtime_or_none(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def watch_file(
    path: Path,
    on_change: Callable[[Path], None],
    interval: float = DEFAULT_POLL_INTERVAL,
    iterations: int | None = None,
) -> int:
    """Block until interrupted, calling `on_change(path)` whenever mtime changes.

    Returns the number of changes observed. `iterations` is an upper bound
    primarily useful for testing — None means run until KeyboardInterrupt.
    """
    if interval <= 0:
        raise ValueError(f"interval must be positive, got {interval}")
    if interval > MAX_POLL_INTERVAL:
        interval = MAX_POLL_INTERVAL

    last = mtime_or_none(path)
    fires = 0
    iteration = 0

    while iterations is None or iteration < iterations:
        time.sleep(interval)
        current = mtime_or_none(path)
        if current is None:
            logger.debug(f"watch target gone: {path}")
        elif last is None or current != last:
            try:
                on_change(path)
                fires += 1
            except Exception as exc:
                logger.error(f"watch callback raised: {type(exc).__name__}: {exc}")
            last = current
        iteration += 1

    return fires
