#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Achievement definitions and unlock detection."""

from dataclasses import dataclass

from wtfguard.state import State


@dataclass(frozen=True)
class Achievement:
    id: str
    threshold: int
    name: str
    color: str
    metric: str
    secret: bool = False


SKIP_ACHIEVEMENTS: tuple[Achievement, ...] = (
    Achievement("skip-10",   10,   "Speed Reader",          "green",  "skips_total"),
    Achievement("skip-50",   50,   "TL;DR Enthusiast",      "green",  "skips_total"),
    Achievement("skip-100",  100,  "Professional Skipper",  "yellow", "skips_total"),
    Achievement("skip-250",  250,  "I Trust No One",        "yellow", "skips_total"),
    Achievement("skip-500",  500,  "Living Dangerously",    "red",    "skips_total"),
    Achievement("skip-1000", 1000, "Senior Skipper",        "magenta", "skips_total", secret=True),
)

READ_ACHIEVEMENTS: tuple[Achievement, ...] = (
    Achievement("read-10",  10,  "Curious Cat",        "cyan",  "reads_total"),
    Achievement("read-50",  50,  "Security-Minded",    "cyan",  "reads_total"),
    Achievement("read-250", 250, "Threat-Intel Nerd",  "blue",  "reads_total"),
)

ALL_ACHIEVEMENTS: tuple[Achievement, ...] = SKIP_ACHIEVEMENTS + READ_ACHIEVEMENTS


def get_metric(state: State, metric: str) -> int:
    return int(getattr(state, metric, 0))


def newly_unlocked(state: State) -> list[Achievement]:
    """Achievements whose threshold the current state has crossed but that are not in state.achievements yet."""
    unlocked: list[Achievement] = []
    already = set(state.achievements)
    for ach in ALL_ACHIEVEMENTS:
        if ach.id in already:
            continue
        if get_metric(state, ach.metric) >= ach.threshold:
            unlocked.append(ach)
    return unlocked


def mark_unlocked(state: State, achievements: list[Achievement]) -> None:
    for ach in achievements:
        if ach.id not in state.achievements:
            state.achievements.append(ach.id)
