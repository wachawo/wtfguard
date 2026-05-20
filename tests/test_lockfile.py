#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the lockfile parsers."""

from pathlib import Path

from wtfguard.lockfile import (
    dedupe_packages,
    detect_format,
    parse_file,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
    strip_version_specifiers,
)


def test_detect_format_by_filename() -> None:
    assert detect_format(Path("poetry.lock")) == "poetry"
    assert detect_format(Path("uv.lock")) == "uv"
    assert detect_format(Path("Pipfile.lock")) == "pipfile"
    assert detect_format(Path("requirements.txt")) == "requirements"
    assert detect_format(Path("requirements.in")) == "requirements"
    assert detect_format(Path("unknown")) == "requirements"


def test_parse_requirements_simple() -> None:
    text = "requests==2.32.0\nnumpy==1.26.0\n"
    assert parse_requirements(text) == [("requests", "2.32.0"), ("numpy", "1.26.0")]


def test_parse_requirements_comments_blanks_dashes() -> None:
    text = (
        "# top comment\n"
        "\n"
        "requests==2.32.0  # pinned\n"
        "-e .\n"
        "-r other-requirements.txt\n"
        "numpy==1.26.0\n"
    )
    result = parse_requirements(text)
    assert result == [("requests", "2.32.0"), ("numpy", "1.26.0")]


def test_parse_requirements_unpinned() -> None:
    text = "requests\nnumpy\n"
    assert parse_requirements(text) == [("requests", None), ("numpy", None)]


def test_parse_requirements_environment_markers() -> None:
    text = "requests==2.32.0 ; python_version > '3.8'\n"
    assert parse_requirements(text) == [("requests", "2.32.0")]


def test_parse_requirements_url_lines_skipped() -> None:
    text = (
        "https://example.com/foo.whl\n"
        "git+https://example.com/bar.git\n"
        "requests==2.32.0\n"
    )
    assert parse_requirements(text) == [("requests", "2.32.0")]


def test_parse_requirements_version_specifiers_stripped() -> None:
    text = "requests>=2.0\nnumpy~=1.26\n"
    assert parse_requirements(text) == [("requests", None), ("numpy", None)]


def test_strip_version_specifiers_known_markers() -> None:
    assert strip_version_specifiers("requests>=2.0") == "requests"
    assert strip_version_specifiers("numpy~=1.26") == "numpy"
    assert strip_version_specifiers("foo[extra]") == "foo"
    assert strip_version_specifiers("foo") == "foo"


def test_parse_poetry_lock() -> None:
    text = """\
[[package]]
name = "requests"
version = "2.32.0"

[[package]]
name = "numpy"
version = "1.26.0"
"""
    assert parse_poetry_lock(text) == [("requests", "2.32.0"), ("numpy", "1.26.0")]


def test_parse_uv_lock_same_format() -> None:
    text = """\
[[package]]
name = "requests"
version = "2.32.0"
"""
    assert parse_uv_lock(text) == [("requests", "2.32.0")]


def test_parse_poetry_lock_no_packages() -> None:
    assert parse_poetry_lock("[metadata]\nlock-version = '2.0'\n") == []


def test_parse_poetry_lock_malformed_entry() -> None:
    text = """\
[[package]]
name = "good"
version = "1.0"

[[package]]
version = "1.0"
"""
    assert parse_poetry_lock(text) == [("good", "1.0")]


def test_parse_poetry_lock_invalid_toml() -> None:
    assert parse_poetry_lock("not [[[ valid toml") == []


def test_parse_pipfile_lock() -> None:
    text = """\
{
    "default": {
        "requests": {"version": "==2.32.0"},
        "numpy":    {"version": "==1.26.0"}
    },
    "develop": {
        "pytest":   {"version": "==8.0.0"}
    }
}
"""
    result = parse_pipfile_lock(text)
    names = {n for n, v in result}
    assert names == {"requests", "numpy", "pytest"}
    versions = dict(result)
    assert versions["requests"] == "2.32.0"


def test_parse_pipfile_lock_invalid_json() -> None:
    assert parse_pipfile_lock("not json") == []


def test_parse_pipfile_lock_missing_sections() -> None:
    assert parse_pipfile_lock("{}") == []


def test_parse_file_auto_detects_poetry(tmp_path: Path) -> None:
    f = tmp_path / "poetry.lock"
    f.write_text("[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n", encoding="utf-8")
    assert parse_file(f) == [("requests", "2.32.0")]


def test_parse_file_auto_detects_pipfile(tmp_path: Path) -> None:
    f = tmp_path / "Pipfile.lock"
    f.write_text('{"default": {"requests": {"version": "==2.32.0"}}}', encoding="utf-8")
    assert parse_file(f) == [("requests", "2.32.0")]


def test_parse_file_unreadable(tmp_path: Path) -> None:
    assert parse_file(tmp_path / "missing.lock") == []


def test_dedupe_preserves_first_occurrence() -> None:
    items = [("Foo", "1.0"), ("foo", "1.0"), ("bar", "2.0"), ("foo_bar", "1.0")]
    result = dedupe_packages(items)
    assert result == [("Foo", "1.0"), ("bar", "2.0"), ("foo_bar", "1.0")]


def test_dedupe_keeps_different_versions() -> None:
    items = [("requests", "2.32.0"), ("requests", "2.31.0")]
    assert dedupe_packages(items) == items
