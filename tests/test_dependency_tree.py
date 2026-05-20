#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for transitive dependency tree resolution."""

from __future__ import annotations

from unittest.mock import patch

from wtfguard.dependency_tree import (
    TreeNode,
    collect_nodes,
    format_tree,
    parse_requires_dist,
    pick_version,
    resolve_tree,
    tree_to_dict,
)


def test_parse_requires_dist_basic() -> None:
    reqs = parse_requires_dist(["requests (>=2.0)", "numpy (==1.26.0)"])
    assert {r.name for r in reqs} == {"requests", "numpy"}


def test_parse_requires_dist_skips_unmatched_markers() -> None:
    # `extra` markers don't evaluate to True by default
    reqs = parse_requires_dist([
        "requests",
        "pytest; extra == 'dev'",
        "pywin32; sys_platform == 'win32-totally-fake'",
    ])
    names = {r.name for r in reqs}
    assert "requests" in names
    assert "pytest" not in names


def test_parse_requires_dist_skips_invalid() -> None:
    reqs = parse_requires_dist(["totally not a requirement string"])
    assert reqs == []


def test_parse_requires_dist_empty() -> None:
    assert parse_requires_dist(None) == []
    assert parse_requires_dist([]) == []


def test_pick_version_eq() -> None:
    from packaging.requirements import Requirement

    assert pick_version(Requirement("foo==1.2.3")) == "1.2.3"


def test_pick_version_inequality_returns_none() -> None:
    from packaging.requirements import Requirement

    assert pick_version(Requirement("foo>=1.2.3")) is None


def test_resolve_tree_root_only_when_no_metadata() -> None:
    with patch("wtfguard.dependency_tree.pypi_signals.fetch_metadata", return_value=None):
        tree = resolve_tree("demo", "1.0")
    assert tree.name == "demo"
    assert tree.version == "1.0"
    assert tree.children == []


def test_resolve_tree_walks_requires_dist() -> None:
    metadata_calls = {
        "demo": {"info": {"requires_dist": ["dep_a (==1.0)", "dep_b (==2.0)"]}, "releases": {}},
        "dep_a": {"info": {"requires_dist": ["dep_c (==3.0)"]}, "releases": {}},
        "dep_b": {"info": {"requires_dist": []}, "releases": {}},
        "dep_c": {"info": {"requires_dist": []}, "releases": {}},
    }

    def fake_fetch(name: str):
        return object() if name in metadata_calls else None

    def fake_pull(name: str):
        return metadata_calls.get(name)

    with patch("wtfguard.dependency_tree.pypi_signals.fetch_metadata", side_effect=fake_fetch), \
         patch("wtfguard.dependency_tree.pypi_signals.pull_pypi_metadata", side_effect=fake_pull):
        tree = resolve_tree("demo", "1.0", max_depth=5)

    children_names = {child.name for child in tree.children}
    assert children_names == {"dep_a", "dep_b"}
    dep_a = next(c for c in tree.children if c.name == "dep_a")
    assert dep_a.children[0].name == "dep_c"


def test_resolve_tree_respects_max_depth() -> None:
    metadata = {
        "demo": {"info": {"requires_dist": ["dep_a (==1.0)"]}, "releases": {}},
        "dep_a": {"info": {"requires_dist": ["dep_b (==2.0)"]}, "releases": {}},
        "dep_b": {"info": {"requires_dist": ["dep_c (==3.0)"]}, "releases": {}},
    }
    with patch("wtfguard.dependency_tree.pypi_signals.fetch_metadata", side_effect=lambda n: object()), \
         patch("wtfguard.dependency_tree.pypi_signals.pull_pypi_metadata", side_effect=lambda n: metadata.get(n)):
        tree = resolve_tree("demo", "1.0", max_depth=2)

    assert tree.children[0].name == "dep_a"
    # dep_a is at depth=1, dep_b would be depth=2 which is max_depth → stops
    assert tree.children[0].children == []


def test_resolve_tree_dedupes_cycles() -> None:
    metadata = {
        "demo": {"info": {"requires_dist": ["dep_a (==1.0)"]}, "releases": {}},
        "dep_a": {"info": {"requires_dist": ["demo (==1.0)"]}, "releases": {}},  # cycle
    }
    with patch("wtfguard.dependency_tree.pypi_signals.fetch_metadata", side_effect=lambda n: object()), \
         patch("wtfguard.dependency_tree.pypi_signals.pull_pypi_metadata", side_effect=lambda n: metadata.get(n)):
        tree = resolve_tree("demo", "1.0", max_depth=5)

    flat_names = [node.name for node in tree.flatten()]
    assert flat_names.count("demo") == 1
    assert flat_names.count("dep_a") == 1


def test_resolve_tree_max_nodes_caps_total() -> None:
    def chain_metadata(n: str):
        # Each node depends on the next: chain_0 -> chain_1 -> ...
        if n.startswith("chain_"):
            i = int(n.split("_")[1])
            return {"info": {"requires_dist": [f"chain_{i+1} (==1.0)"]}, "releases": {}}
        return None

    with patch("wtfguard.dependency_tree.pypi_signals.fetch_metadata", side_effect=lambda n: object()), \
         patch("wtfguard.dependency_tree.pypi_signals.pull_pypi_metadata", side_effect=chain_metadata):
        tree = resolve_tree("chain_0", "1.0", max_depth=50, max_nodes=5)

    assert len(tree.flatten()) <= 6


def test_collect_nodes_dfs_dedup() -> None:
    tree = TreeNode("a", "1", 0, children=[
        TreeNode("b", "1", 1, children=[
            TreeNode("c", "1", 2),
        ]),
        TreeNode("c", "1", 1),  # duplicate of c at different depth
    ])
    nodes = collect_nodes(tree)
    names = [name for name, _ in nodes]
    assert names == ["a", "b", "c"]


def test_format_tree_indentation() -> None:
    tree = TreeNode("a", "1", 0, children=[TreeNode("b", "2", 1)])
    text = format_tree(tree)
    assert "a==1" in text
    assert "  b==2" in text


def test_tree_to_dict() -> None:
    tree = TreeNode("a", "1", 0, children=[TreeNode("b", None, 1)])
    d = tree_to_dict(tree)
    assert d["name"] == "a"
    assert d["children"][0]["name"] == "b"
    assert d["children"][0]["version"] is None
