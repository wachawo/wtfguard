#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the tip streamer."""

import json
import threading
import time
from pathlib import Path

from wtfguard.tips import Tip, TipStreamer, load_tips, random_tip, sample_tips


def test_load_tips_returns_nonempty_list() -> None:
    tips = load_tips()
    assert len(tips) >= 10
    assert all(isinstance(t, Tip) for t in tips)
    assert all(t.id and t.level and t.text for t in tips)


def test_load_tips_custom_path(tmp_path: Path) -> None:
    custom = tmp_path / "tips.json"
    custom.write_text(
        json.dumps([{"id": "x", "level": "joke", "text": "foo"}]),
        encoding="utf-8",
    )
    tips = load_tips(custom)
    assert len(tips) == 1
    assert tips[0].id == "x"
    assert tips[0].level == "joke"


def test_sample_tips_respects_n() -> None:
    tips = load_tips()
    sampled = sample_tips(tips, 3, seed=42)
    assert len(sampled) == 3


def test_sample_tips_seed_reproducible() -> None:
    tips = load_tips()
    a = sample_tips(tips, 5, seed=7)
    b = sample_tips(tips, 5, seed=7)
    assert [t.id for t in a] == [t.id for t in b]


def test_sample_tips_zero_returns_empty() -> None:
    tips = load_tips()
    assert sample_tips(tips, 0) == []


def test_random_tip_returns_a_tip() -> None:
    t = random_tip(seed=1)
    assert isinstance(t, Tip)
    assert t.text


def test_tip_streamer_emits_at_least_once() -> None:
    tips = [Tip(id="x", level="joke", text="hi")]
    seen: list[Tip] = []
    event = threading.Event()

    def on_tip(t: Tip) -> None:
        seen.append(t)
        event.set()

    streamer = TipStreamer(tips=tips, on_tip=on_tip, interval=0.05)
    streamer.start()
    try:
        assert event.wait(timeout=2.0), "tip never emitted"
    finally:
        streamer.stop()
    assert seen
    assert seen[0].id == "x"


def test_tip_streamer_stop_is_idempotent() -> None:
    tips = [Tip(id="x", level="joke", text="hi")]
    streamer = TipStreamer(tips=tips, on_tip=lambda t: None, interval=0.05)
    streamer.start()
    time.sleep(0.1)
    streamer.stop()
    streamer.stop()  # second call must not raise


def test_tip_streamer_start_twice_no_double_thread() -> None:
    streamer = TipStreamer(tips=[Tip(id="x", level="joke", text="hi")], on_tip=lambda t: None, interval=0.05)
    streamer.start()
    first_thread = streamer.thread
    streamer.start()
    assert streamer.thread is first_thread
    streamer.stop()


def test_tip_streamer_empty_tips_exits_cleanly() -> None:
    streamer = TipStreamer(tips=[], on_tip=lambda t: None, interval=0.05)
    streamer.start()
    time.sleep(0.05)
    streamer.stop()


def test_tip_streamer_handles_callback_exception() -> None:
    tips = [Tip(id="x", level="joke", text="hi")]
    call_count = [0]
    event = threading.Event()

    def on_tip(t: Tip) -> None:
        call_count[0] += 1
        if call_count[0] >= 2:
            event.set()
        raise RuntimeError("test")

    streamer = TipStreamer(tips=tips, on_tip=on_tip, interval=0.05)
    streamer.start()
    try:
        assert event.wait(timeout=2.0), "streamer died on exception"
    finally:
        streamer.stop()
    assert call_count[0] >= 2
