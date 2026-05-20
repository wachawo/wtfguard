#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tip streamer — emits security tips during scan in --talkative mode."""

import json
import logging
import random
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TIPS_PATH = Path(__file__).parent / "data" / "tips.json"


@dataclass(frozen=True)
class Tip:
    id: str
    level: str
    text: str


def load_tips(path: Path | None = None) -> list[Tip]:
    tips_path = path or DEFAULT_TIPS_PATH
    with tips_path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return [Tip(id=item["id"], level=item["level"], text=item["text"]) for item in raw]


def sample_tips(tips: Iterable[Tip], n: int, seed: int | None = None) -> list[Tip]:
    rng = random.Random(seed)
    pool = list(tips)
    rng.shuffle(pool)
    return pool[:n]


class TipStreamer:
    """Background tip emitter. Calls on_tip(tip) every interval seconds until stopped."""

    def __init__(
        self,
        tips: list[Tip],
        on_tip: Callable[[Tip], None],
        interval: float = 4.0,
    ):
        self.tips = tips
        self.on_tip = on_tip
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread is not None:
            return
        self.thread = threading.Thread(target=self.run_loop, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=self.interval + 1.0)
            self.thread = None

    def run_loop(self) -> None:
        pool = list(self.tips)
        if not pool:
            return
        random.shuffle(pool)
        index = 0
        while not self.stop_event.is_set():
            tip = pool[index % len(pool)]
            try:
                self.on_tip(tip)
            except Exception as exc:
                logger.warning(f"Tip emitter error: {type(exc).__name__}: {exc}")
            index += 1
            self.stop_event.wait(self.interval)


def random_tip(seed: int | None = None) -> Tip:
    tips = load_tips()
    rng = random.Random(seed)
    return rng.choice(tips)
