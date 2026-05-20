#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unified diff between two extracted package trees."""

import difflib
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DIFF_TEXT_EXTENSIONS = frozenset({".py", ".pyi", ".cfg", ".toml", ".txt", ".md", ".ini"})
DIFF_INSTALL_FILES = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "MANIFEST.in"})
DIFF_CONTEXT_LINES = 3


@dataclass(frozen=True)
class FileDiff:
    path: str
    status: str
    body: str

    def is_meaningful(self) -> bool:
        return self.status != "unchanged" and bool(self.body.strip())


def relative_files(root: Path) -> dict[str, Path]:
    """Map relative-path -> absolute-path for all interesting text files under root."""
    out: dict[str, Path] = {}
    if not root.exists():
        return out
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix in DIFF_TEXT_EXTENSIONS or p.name in DIFF_INSTALL_FILES:
            rel = p.relative_to(root).as_posix()
            out[rel] = p
    return out


def file_diff(rel_path: str, old: Path | None, new: Path | None) -> FileDiff:
    """Produce unified diff between two files. Either side may be None (added/removed)."""
    old_text = read_text_safe(old) if old else ""
    new_text = read_text_safe(new) if new else ""

    if old is None and new is not None:
        status = "added"
    elif old is not None and new is None:
        status = "removed"
    elif old_text == new_text:
        status = "unchanged"
    else:
        status = "modified"

    body = "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            n=DIFF_CONTEXT_LINES,
        )
    )
    return FileDiff(path=rel_path, status=status, body=body)


def read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning(f"Cannot read {path}: {type(exc).__name__}: {exc}")
        return ""


def tree_diff(old_root: Path, new_root: Path) -> list[FileDiff]:
    """Diff every relevant text file between two package trees."""
    old_files = relative_files(old_root)
    new_files = relative_files(new_root)
    paths = sorted(set(old_files) | set(new_files))

    diffs: list[FileDiff] = []
    for rel in paths:
        diffs.append(file_diff(rel, old_files.get(rel), new_files.get(rel)))
    return diffs


def diff_hash(diffs: list[FileDiff]) -> str:
    """Stable sha256 over (path, status, body) tuples — used as cache key."""
    hasher = hashlib.sha256()
    for d in sorted(diffs, key=lambda x: x.path):
        hasher.update(d.path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(d.status.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(d.body.encode("utf-8", errors="replace"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def meaningful_diffs(diffs: list[FileDiff]) -> list[FileDiff]:
    return [d for d in diffs if d.is_meaningful()]
