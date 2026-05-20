#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Concurrent execution helper for scanning multiple packages.

Uses a thread pool — analyzer work is I/O-bound (PyPI download, optional
LLM call), so threads are the right tool. Order of results matches the
order of inputs for stable, reproducible output.
"""

import logging
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


def map_parallel(
    func: Callable[[T], R],
    items: Iterable[T],
    jobs: int,
    on_error: Callable[[T, BaseException], R | None] | None = None,
) -> list[R]:
    """Apply `func` to each item with up to `jobs` worker threads.

    Returns results in the same order as `items`. If `func` raises and
    `on_error` is provided, the handler is called with (item, exception)
    and may return a substitute result (or None to drop the item).
    """
    item_list = list(items)
    if jobs <= 1 or len(item_list) <= 1:
        return run_sequential(func, item_list, on_error)

    results: list[R | None] = [None] * len(item_list)
    with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="wtfguard") as pool:
        future_to_index = {pool.submit(func, item): idx for idx, item in enumerate(item_list)}
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                results[idx] = future.result()
            except BaseException as exc:
                if on_error is not None:
                    results[idx] = on_error(item_list[idx], exc)
                else:
                    logger.error(f"{type(exc).__name__}: {exc}")
                    raise
    return [r for r in results if r is not None]


def run_sequential(
    func: Callable[[T], R],
    items: list[T],
    on_error: Callable[[T, BaseException], R | None] | None,
) -> list[R]:
    out: list[R] = []
    for item in items:
        try:
            out.append(func(item))
        except BaseException as exc:
            if on_error is None:
                raise
            substitute = on_error(item, exc)
            if substitute is not None:
                out.append(substitute)
    return out
