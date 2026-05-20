#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Package allowlist — skip scanning for explicitly trusted packages.

Search order (first match wins):
1. `.wtfguardignore` in the current working directory
2. `WTFGUARD_ALLOWLIST` env var (path to a file)
3. `~/.wtfguard/allowlist.txt`

File format: one entry per line, blank lines and `#`-comments ignored.
Each entry is either:
- a bare package name (e.g. `requests`) — matches any version
- a pinned spec (e.g. `requests==2.32.0`) — matches only that version
- a glob-style prefix (e.g. `internal-*`) — matches packages starting with prefix
"""

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from wtfguard.utils import normalize_name as _pep503

logger = logging.getLogger(__name__)

ENV_VAR = "WTFGUARD_ALLOWLIST"
LOCAL_FILENAME = ".wtfguardignore"
DEFAULT_PATH = Path.home() / ".wtfguard" / "allowlist.txt"


@dataclass(frozen=True)
class Allowlist:
    bare:    frozenset[str] = field(default_factory=frozenset)
    pinned:  frozenset[tuple[str, str]] = field(default_factory=frozenset)
    globs:   tuple[str, ...] = ()

    def allows(self, package: str, version: str | None) -> bool:
        pkg = normalize(package)
        if pkg in self.bare:
            return True
        if version is not None and (pkg, version) in self.pinned:
            return True
        return any(fnmatch.fnmatchcase(pkg, pattern) for pattern in self.globs)


def normalize(name: str) -> str:
    """Wrapper around the PEP 503 normalizer for backwards compatibility."""
    return _pep503(name)


def discover_path(start_dir: Path | None = None) -> Path | None:
    """Return the first allowlist path that exists, or None."""
    if start_dir is None:
        start_dir = Path.cwd()
    local = start_dir / LOCAL_FILENAME
    if local.is_file():
        return local

    env_value = os.getenv(ENV_VAR)
    if env_value:
        env_path = Path(env_value)
        if env_path.is_file():
            return env_path

    if DEFAULT_PATH.is_file():
        return DEFAULT_PATH

    return None


def load(path: Path | None = None) -> Allowlist:
    """Load an allowlist from a specific path, or auto-discover one."""
    resolved = path or discover_path()
    if resolved is None:
        return Allowlist()

    bare: set[str] = set()
    pinned: set[tuple[str, str]] = set()
    globs: list[str] = []

    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning(f"Cannot read allowlist {resolved}: {type(exc).__name__}: {exc}")
        return Allowlist()

    try:
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                pinned.add((normalize(name), version.strip()))
                continue
            normalized = normalize(line)
            if any(ch in normalized for ch in "*?["):
                globs.append(normalized)
            else:
                bare.add(normalized)
    except ValueError as exc:
        logger.warning(f"Cannot parse allowlist {resolved}: {type(exc).__name__}: {exc}")
        return Allowlist()

    logger.info(f"Loaded allowlist {resolved}: {len(bare)} bare, {len(pinned)} pinned, {len(globs)} globs")
    return Allowlist(
        bare=frozenset(bare),
        pinned=frozenset(pinned),
        globs=tuple(globs),
    )
