#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Typosquat detection — fifth detection axis.

Compare a package name against a curated list of high-traffic PyPI
packages. If the candidate is within edit distance N of a popular name
but is NOT the popular name itself, flag it as a typosquat candidate.
This is the entry point for most published supply-chain attacks
(requests → requessts, ultralytics → ultralytics-utils, etc.).

The bundled allowlist is small (top ~100 packages). For production use,
this list should be expanded — a future `wtfguard refresh-popular`
command can pull the live top-N from BigQuery or pypistats.

Edit distance is Levenshtein. Confusable character substitutions
(0/o, 1/l, rn/m) are not yet considered — that is the obvious next step.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from wtfguard.models import Finding, Severity
from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)

POPULAR_PATH = Path(__file__).parent / "data" / "popular_pypi.txt"
DEFAULT_MAX_DISTANCE = 2
SHORT_NAME_LIMIT = 4

# Visually-confusable substitutions. Each value is the canonical character
# the key can be mistaken for. Bidirectional pairs are listed twice for
# clarity. Multi-char keys like "rn"/"m" are also handled.
CONFUSABLE_SINGLE: dict[str, str] = {
    "0": "o", "o": "0",
    "1": "l", "l": "1",
    "5": "s", "s": "5",
    "2": "z", "z": "2",
    "i": "l",
    "vv": "w",
    "w": "vv",
}
CONFUSABLE_MULTI: dict[str, str] = {
    "rn": "m",
    "m":  "rn",
    "cl": "d",
    "d":  "cl",
}


def load_popular(path: Path | None = None) -> frozenset[str]:
    """Read the bundled list of normalized popular package names."""
    target = path or POPULAR_PATH
    if not target.is_file():
        logger.warning(f"Popular list missing: {target}")
        return frozenset()
    out: set[str] = set()
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.add(normalize_name(line))
    return frozenset(out)


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (0 if ca == cb else 1)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def confusable_variants(name: str) -> set[str]:
    """Generate visually-confusable variants of `name`.

    Each variant applies ONE substitution from CONFUSABLE_SINGLE or
    CONFUSABLE_MULTI. The original name is included in the result. Used to
    catch typosquats that Levenshtein misses because the visual swap costs
    more than max_distance edits (e.g. `rn` -> `m` is 2 Levenshtein ops).
    """
    variants: set[str] = {name}

    for src, dst in CONFUSABLE_MULTI.items():
        if src in name:
            variants.add(name.replace(src, dst, 1))

    for i, ch in enumerate(name):
        replacement = CONFUSABLE_SINGLE.get(ch)
        if replacement is not None:
            variants.add(name[:i] + replacement + name[i + 1 :])

    return variants


def find_near_matches(
    candidate: str,
    popular: Iterable[str],
    max_distance: int = DEFAULT_MAX_DISTANCE,
) -> list[tuple[str, int]]:
    """Return (popular_name, distance) pairs within max_distance of candidate.

    Excludes the exact match — a name that IS in the popular list is
    legitimate by definition. Sorted by distance ascending. Considers
    confusable-substitution variants of the candidate too.
    """
    canon = normalize_name(candidate)
    if not canon:
        return []
    popular_set = set(popular)

    if canon in popular_set:
        return []  # legitimate package

    candidates = confusable_variants(canon)
    matches: dict[str, int] = {}

    for variant in candidates:
        for name in popular_set:
            if name == canon:
                continue
            if abs(len(name) - len(variant)) > max_distance:
                continue
            d = levenshtein(variant, name)
            if 0 < d <= max_distance:
                prev = matches.get(name)
                if prev is None or d < prev:
                    matches[name] = d

    return sorted(matches.items(), key=lambda pair: (pair[1], pair[0]))


def check(name: str, popular: Iterable[str] | None = None, max_distance: int = DEFAULT_MAX_DISTANCE) -> list[Finding]:
    """Return typosquat findings for the given candidate name.

    Short names (<= SHORT_NAME_LIMIT chars) are skipped — edit distance is
    unreliable on tiny strings, and most short names are bare letters that
    legitimately appear all over PyPI.
    """
    canon = normalize_name(name)
    if len(canon) <= SHORT_NAME_LIMIT:
        return []
    pop = frozenset(popular) if popular is not None else load_popular()
    matches = find_near_matches(canon, pop, max_distance)
    if not matches:
        return []
    closest_name, closest_distance = matches[0]
    severity = Severity.HIGH if closest_distance == 1 else Severity.MEDIUM
    near_str = ", ".join(f"{n} (d={d})" for n, d in matches[:3])
    return [
        Finding(
            rule_id="TYPOSQUAT_CANDIDATE",
            severity=severity,
            file=f"<name:{canon}>",
            line=1,
            snippet=f"near {near_str}",
            description=f"Name resembles popular package '{closest_name}' (edit distance {closest_distance}) — possible typosquat",
        )
    ]
