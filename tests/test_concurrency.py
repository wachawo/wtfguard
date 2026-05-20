#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the concurrency helper."""

import threading
import time

import pytest

from wtfguard.concurrency import map_parallel, run_sequential


def test_sequential_preserves_order() -> None:
    out = map_parallel(lambda x: x * 2, [1, 2, 3, 4], jobs=1)
    assert out == [2, 4, 6, 8]


def test_parallel_preserves_order() -> None:
    out = map_parallel(lambda x: x * 2, [1, 2, 3, 4, 5], jobs=4)
    assert out == [2, 4, 6, 8, 10]


def test_empty_input() -> None:
    assert map_parallel(lambda x: x, [], jobs=4) == []


def test_single_item_uses_sequential_path() -> None:
    out = map_parallel(lambda x: x + 100, [7], jobs=4)
    assert out == [107]


def test_parallel_actually_runs_concurrently() -> None:
    barrier = threading.Barrier(4)

    def slow(_x: int) -> int:
        barrier.wait(timeout=2.0)
        return 1

    start = time.monotonic()
    out = map_parallel(slow, [0, 0, 0, 0], jobs=4)
    elapsed = time.monotonic() - start
    assert out == [1, 1, 1, 1]
    assert elapsed < 2.0, f"sequential would have hung at barrier; elapsed={elapsed}"


def test_on_error_handler_receives_exception() -> None:
    seen: list[tuple[int, type[BaseException]]] = []

    def maybe_raise(x: int) -> int:
        if x == 2:
            raise ValueError("nope")
        return x

    def handler(item: int, exc: BaseException) -> int | None:
        seen.append((item, type(exc)))
        return -1

    out = map_parallel(maybe_raise, [1, 2, 3], jobs=2, on_error=handler)
    assert sorted(out) == sorted([1, -1, 3])
    assert (2, ValueError) in seen


def test_on_error_can_drop_item() -> None:
    def maybe_raise(x: int) -> int:
        if x == 2:
            raise ValueError("nope")
        return x

    out = map_parallel(maybe_raise, [1, 2, 3], jobs=2, on_error=lambda item, exc: None)
    assert sorted(out) == [1, 3]


def test_exception_without_handler_propagates() -> None:
    def boom(x: int) -> int:
        if x == 1:
            raise ValueError("nope")
        return x

    with pytest.raises(ValueError):
        map_parallel(boom, [0, 1, 2], jobs=2)


def test_run_sequential_propagates_without_handler() -> None:
    with pytest.raises(RuntimeError):
        run_sequential(lambda x: (_ for _ in ()).throw(RuntimeError("x")) if x else x, [1], on_error=None)


def test_run_sequential_with_handler() -> None:
    out = run_sequential(
        lambda x: x if x else (_ for _ in ()).throw(RuntimeError("x")),
        [0, 1, 2],
        on_error=lambda item, exc: -1,
    )
    assert out == [-1, 1, 2]


def test_jobs_le_zero_falls_back_to_sequential() -> None:
    out = map_parallel(lambda x: x, [1, 2, 3], jobs=0)
    assert out == [1, 2, 3]
