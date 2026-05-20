#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User-local state: skip counter, read counter, unlocked achievements."""

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_STATE_PATH = Path.home() / ".wtfguard" / "state.json"


@dataclass
class State:
    skips_total:   int = 0
    reads_total:   int = 0
    scans_total:   int = 0
    achievements:  list[str] = field(default_factory=list)
    talkative:     bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def load_state(path: Path | None = None) -> State:
    state_path = path or DEFAULT_STATE_PATH
    if not state_path.exists():
        return State()
    try:
        with state_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return State(
            skips_total=int(data.get("skips_total", 0)),
            reads_total=int(data.get("reads_total", 0)),
            scans_total=int(data.get("scans_total", 0)),
            achievements=list(data.get("achievements", [])),
            talkative=bool(data.get("talkative", False)),
        )
    except (OSError, ValueError) as exc:
        logger.warning(f"Cannot load state {state_path}: {type(exc).__name__}: {exc}")
        return State()


def save_state(state: State, path: Path | None = None) -> None:
    state_path = path or DEFAULT_STATE_PATH
    state_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with state_path.open("w", encoding="utf-8") as fh:
            json.dump(state.to_dict(), fh, indent=2, ensure_ascii=False)
    except OSError as exc:
        logger.warning(f"Cannot save state {state_path}: {type(exc).__name__}: {exc}")
