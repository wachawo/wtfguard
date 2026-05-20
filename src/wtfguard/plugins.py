#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Discover third-party rule packs via setuptools entry-points.

A community plugin declares itself in its own pyproject.toml:

    [project.entry-points."wtfguard.rules"]
    my-team-rules = "my_team_pkg:rules_path"

The entry-point target must be a string `module:attribute` where the
attribute resolves to either:
- a path (str or Path) to a YAML rules file, OR
- a callable returning such a path.

Plugins are discovered lazily on the first `heuristics.load_rules`
call. Failures are logged and the plugin is skipped — a broken third-
party plugin never breaks wtfguard itself.
"""

from __future__ import annotations

import logging
from importlib import metadata
from pathlib import Path

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "wtfguard.rules"


def discover_rule_paths() -> list[Path]:
    """Return paths to rule YAML files from every installed `wtfguard.rules` entry-point.

    Order is whatever `importlib.metadata.entry_points()` returns; bundled
    rules always come first because the caller passes them as `yaml_path`,
    so plugin overrides work the same way as `--rules`.
    """
    out: list[Path] = []
    try:
        entry_points = _entry_points_for_group(ENTRY_POINT_GROUP)
    except Exception as exc:
        logger.warning(f"Cannot enumerate entry points for {ENTRY_POINT_GROUP}: {type(exc).__name__}: {exc}")
        return out

    for ep in entry_points:
        try:
            target = ep.load()
        except Exception as exc:
            logger.warning(f"Plugin {ep.name} failed to load: {type(exc).__name__}: {exc}")
            continue

        resolved = resolve_target(ep.name, target)
        if resolved is not None:
            out.append(resolved)
    return out


def _entry_points_for_group(group: str) -> list[metadata.EntryPoint]:
    """importlib.metadata.entry_points has different APIs across Python versions."""
    raw = metadata.entry_points()
    selector = getattr(raw, "select", None)
    if callable(selector):
        return list(selector(group=group))
    # Python 3.9 fallback: dict-like mapping
    return list(raw.get(group, []) if hasattr(raw, "get") else [])


def resolve_target(plugin_name: str, target: object) -> Path | None:
    """Allow the entry-point to be a Path, a str, or a callable returning either."""
    if callable(target):
        try:
            target = target()
        except Exception as exc:
            logger.warning(f"Plugin {plugin_name} callable failed: {type(exc).__name__}: {exc}")
            return None

    if isinstance(target, Path):
        return target_or_warn(plugin_name, target)
    if isinstance(target, str):
        return target_or_warn(plugin_name, Path(target))

    logger.warning(f"Plugin {plugin_name} returned an unsupported target type: {type(target).__name__}")
    return None


def target_or_warn(plugin_name: str, path: Path) -> Path | None:
    if not path.is_file():
        logger.warning(f"Plugin {plugin_name} points at missing file: {path}")
        return None
    return path
