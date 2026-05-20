#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verdict baseline support — pin a scan result, fail the build when it drifts.

The CI workflow:
1. Run a clean scan once: `wtfguard scan-requirements req.txt --json > baseline.json`
2. Commit `baseline.json` to the repo
3. On every PR / push, `wtfguard verify-baseline baseline.json` re-runs the
   scan and diffs against the committed file. Any new finding fails the
   build until either the offending package is removed or the baseline is
   updated explicitly.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from wtfguard.models import Verdict


def load_baseline(path: Path) -> dict[str, Any]:
    """Parse a baseline JSON. Returns the parsed object; raises ValueError on misshape."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object, got {type(data).__name__}")
    return data


def extract_specs(baseline: dict[str, Any]) -> list[tuple[str, str | None]]:
    """Pull (name, version) tuples from baseline — supports single-scan and batch shapes."""
    verdicts = baseline.get("verdicts")
    if isinstance(verdicts, list):
        return [
            (str(v["package"]), str(v.get("version")) if v.get("version") else None)
            for v in verdicts
            if isinstance(v, dict) and v.get("package")
        ]
    pkg = baseline.get("package")
    if isinstance(pkg, str) and pkg:
        return [(pkg, str(baseline.get("version")) if baseline.get("version") else None)]
    return []


def verdicts_to_payload(verdicts: Iterable[Verdict], worst_label: str) -> dict[str, Any]:
    """Re-serialise scan output in the same shape `scan-requirements --json` emits."""
    return {
        "verdicts":    [v.to_dict() for v in verdicts],
        "allowlisted": [],
        "worst":       worst_label,
    }
