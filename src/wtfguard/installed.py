#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discover packages currently installed in the active Python environment."""

import logging
from dataclasses import dataclass
from importlib import metadata

from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)

STDLIB_DISTRIBUTIONS = frozenset({"pip", "setuptools", "wheel", "packaging"})


@dataclass(frozen=True)
class InstalledPackage:
    name: str
    version: str


def list_installed(include_stdlib: bool = False) -> list[InstalledPackage]:
    """Return distributions installed in the current interpreter.

    By default skips bootstrap packages (pip, setuptools, wheel, packaging)
    that are unlikely to be the target of a supply-chain audit.
    """
    out: list[InstalledPackage] = []
    seen: set[str] = set()

    for dist in metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except (KeyError, AttributeError) as exc:
            logger.debug(f"Skipping malformed distribution: {type(exc).__name__}: {exc}")
            continue

        if not name:
            continue
        normalized = normalize_name(name)
        if normalized in seen:
            continue
        seen.add(normalized)

        if not include_stdlib and normalized in STDLIB_DISTRIBUTIONS:
            continue

        out.append(InstalledPackage(name=name, version=version))

    out.sort(key=lambda p: p.name.lower())
    return out
