#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resolve a package's transitive dependency tree from PyPI metadata.

A direct scan of `requests==2.32.0` audits one package. Most supply-chain
attacks ride in transitive dependencies — the one you didn't choose
but `pip install requests` pulled anyway. This module walks the
`requires_dist` field from PyPI JSON and produces the full tree (capped at
a configurable depth), with per-node parsing of PEP 508 marker expressions
so we drop extras / platform-specific deps a normal install would skip.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from packaging.requirements import InvalidRequirement, Requirement

from wtfguard import pypi_signals
from wtfguard.utils import normalize_name

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_NODES = 200


@dataclass
class TreeNode:
    name:     str
    version:  str | None
    depth:    int
    children: list[TreeNode] = field(default_factory=list)

    def flatten(self) -> list[TreeNode]:
        out = [self]
        for child in self.children:
            out.extend(child.flatten())
        return out


def parse_requires_dist(raw: list[str] | None) -> list[Requirement]:
    """Parse PyPI `info.requires_dist` strings into Requirement objects.

    Entries with environment markers that DO NOT match the current env are
    dropped — e.g. `pywin32; sys_platform == "win32"` is ignored on Linux.
    Entries with extras (`requests[security]`) are also dropped — extras
    are opt-in by definition; scanning them by default would double-flag
    everyone using `requests`.
    """
    out: list[Requirement] = []
    for entry in raw or []:
        if not isinstance(entry, str) or not entry.strip():
            continue
        try:
            req = Requirement(entry)
        except InvalidRequirement as exc:
            logger.debug(f"Skipping unparseable requires_dist entry {entry!r}: {exc}")
            continue
        if req.marker is not None and not req.marker.evaluate():
            continue
        out.append(req)
    return out


def resolve_tree(
    root_name: str,
    root_version: str | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> TreeNode:
    """Walk the requires_dist tree starting at root_name."""
    seen: dict[str, str | None] = {}
    counter = [0]

    def walk(name: str, version: str | None, depth: int) -> TreeNode:
        canonical = normalize_name(name)
        node = TreeNode(name=name, version=version, depth=depth)
        # max_depth is total levels of nodes (root inclusive). With max_depth=2
        # we want { root, root.children } only — root.children's children get
        # the depth+1 check below.
        if counter[0] >= max_nodes or depth + 1 >= max_depth:
            return node
        if canonical in seen:
            return node
        seen[canonical] = version
        counter[0] += 1

        metadata = pypi_signals.fetch_metadata(name)
        if metadata is None:
            return node
        raw = pypi_signals.pull_pypi_metadata(name)
        if raw is None:
            return node
        info = raw.get("info") if isinstance(raw, dict) else None
        if not isinstance(info, dict):
            return node
        requires = info.get("requires_dist")
        if not isinstance(requires, list):
            return node

        for req in parse_requires_dist(requires):
            child_version = pick_version(req) or None
            if normalize_name(req.name) in seen:
                continue
            child = walk(req.name, child_version, depth + 1)
            node.children.append(child)
            if counter[0] >= max_nodes:
                break
        return node

    return walk(root_name, root_version, 0)


def pick_version(req: Requirement) -> str | None:
    """Best-effort: pull a concrete pinned version from `==` or `===` specifiers."""
    for spec in req.specifier:
        if spec.operator in ("==", "==="):
            return spec.version
    return None


def collect_nodes(tree: TreeNode) -> list[tuple[str, str | None]]:
    """Return PEP 503 deduped (name, version) tuples in DFS order."""
    seen: set[str] = set()
    out: list[tuple[str, str | None]] = []
    for node in tree.flatten():
        canonical = normalize_name(node.name)
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append((node.name, node.version))
    return out


def format_tree(tree: TreeNode) -> str:
    """Render the tree as an indented ASCII listing."""
    lines: list[str] = []

    def emit(node: TreeNode, prefix: str = "") -> None:
        version_str = f"=={node.version}" if node.version else ""
        lines.append(f"{prefix}{node.name}{version_str}")
        for child in node.children:
            emit(child, prefix + "  ")

    emit(tree)
    return "\n".join(lines)


def tree_to_dict(tree: TreeNode) -> dict[str, Any]:
    return {
        "name":     tree.name,
        "version":  tree.version,
        "depth":    tree.depth,
        "children": [tree_to_dict(c) for c in tree.children],
    }
