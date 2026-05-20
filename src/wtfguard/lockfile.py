#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lock-file parsers: poetry.lock, uv.lock, Pipfile.lock, requirements.txt / .in.

Each parser is pure: takes file text + filename and returns a list of
`(name, version)` tuples. Version may be `None` for unpinned entries.
"""

import json
import logging
import tomllib
from collections.abc import Iterable
from pathlib import Path

from wtfguard.utils import normalize_name

logger = logging.getLogger(__name__)

REQUIREMENTS_EXTENSIONS = frozenset({".txt", ".in"})
PIPFILE_LOCK_NAME = "Pipfile.lock"
POETRY_LOCK_NAME = "poetry.lock"
UV_LOCK_NAME = "uv.lock"


def detect_format(path: Path) -> str:
    """Return one of: poetry, uv, pipfile, requirements. Heuristics by name then extension."""
    name = path.name.lower()
    if name == POETRY_LOCK_NAME:
        return "poetry"
    if name == UV_LOCK_NAME:
        return "uv"
    if name == PIPFILE_LOCK_NAME.lower():
        return "pipfile"
    if path.suffix in REQUIREMENTS_EXTENSIONS or name == "requirements":
        return "requirements"
    return "requirements"


def parse_file(path: Path) -> list[tuple[str, str | None]]:
    """Auto-detect format and parse. Empty list on errors."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Cannot read {path}: {type(exc).__name__}: {exc}")
        return []

    fmt = detect_format(path)
    if fmt == "poetry":
        return parse_poetry_lock(text)
    if fmt == "uv":
        return parse_uv_lock(text)
    if fmt == "pipfile":
        return parse_pipfile_lock(text)
    return parse_requirements(text)


def parse_requirements(text: str) -> list[tuple[str, str | None]]:
    """Parse pip-style requirements.txt or requirements.in."""
    out: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if line.startswith(("http://", "https://", "git+", "file://")):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            version = version.split(";")[0].split(" ")[0].split("--")[0].strip()
            out.append((name.strip(), version))
        else:
            cleaned = line.split(";")[0].split(" ")[0].strip()
            cleaned = strip_version_specifiers(cleaned)
            if cleaned:
                out.append((cleaned, None))
    return out


def strip_version_specifiers(spec: str) -> str:
    """Strip >=, <=, ~=, !=, > or < specifiers, returning the bare package name."""
    for marker in (">=", "<=", "~=", "!=", ">", "<"):
        if marker in spec:
            spec = spec.split(marker, 1)[0]
    return spec.strip().split("[")[0].strip()


def parse_poetry_lock(text: str) -> list[tuple[str, str | None]]:
    """Parse poetry.lock — TOML with [[package]] arrays."""
    return parse_toml_packages(text, key="package")


def parse_uv_lock(text: str) -> list[tuple[str, str | None]]:
    """Parse uv.lock — same TOML [[package]] format as poetry."""
    return parse_toml_packages(text, key="package")


def parse_toml_packages(text: str, key: str) -> list[tuple[str, str | None]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        logger.warning(f"TOML parse failed: {type(exc).__name__}: {exc}")
        return []
    items = data.get(key) or []
    if not isinstance(items, list):
        return []
    out: list[tuple[str, str | None]] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if isinstance(name, str) and name:
            out.append((name, version if isinstance(version, str) else None))
    return out


def parse_pipfile_lock(text: str) -> list[tuple[str, str | None]]:
    """Parse Pipfile.lock — JSON with top-level 'default' and 'develop' tables."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning(f"Pipfile.lock JSON parse failed: {exc}")
        return []
    out: list[tuple[str, str | None]] = []
    for section_name in ("default", "develop"):
        section = data.get(section_name) or {}
        if not isinstance(section, dict):
            continue
        for name, info in section.items():
            if not isinstance(name, str) or not name:
                continue
            version: str | None = None
            if isinstance(info, dict):
                raw = info.get("version")
                if isinstance(raw, str):
                    version = raw.lstrip("=").strip() or None
            out.append((name, version))
    return out


def dedupe_packages(items: Iterable[tuple[str, str | None]]) -> list[tuple[str, str | None]]:
    """Return items in input order with PEP 503 name+version duplicates removed."""
    seen: set[tuple[str, str | None]] = set()
    out: list[tuple[str, str | None]] = []
    for name, version in items:
        key = (normalize_name(name), version)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, version))
    return out
