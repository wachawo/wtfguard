#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the TOML config loader."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from wtfguard.config import (
    Config,
    apply_to_env,
    discover_path,
    load,
    parse_allowlist,
    parse_llm,
    parse_scan,
    string_or_none,
)


def test_string_or_none_strips_whitespace() -> None:
    assert string_or_none("  foo  ") == "foo"
    assert string_or_none("") is None
    assert string_or_none("   ") is None
    assert string_or_none(None) is None
    assert string_or_none(123) is None


def test_parse_scan_section() -> None:
    section = parse_scan({"jobs": 8, "no_llm": True})
    assert section.jobs == 8
    assert section.no_llm is True
    assert section.no_cache is None


def test_parse_scan_ignores_wrong_types() -> None:
    section = parse_scan({"jobs": "eight"})
    assert section.jobs is None


def test_parse_llm_section() -> None:
    section = parse_llm({
        "backend":           "ollama",
        "model":             "qwen2.5-coder:32b",
        "ollama_url":        "http://gpu:11434",
        "anthropic_api_key": "sk-test",
    })
    assert section.backend == "ollama"
    assert section.model == "qwen2.5-coder:32b"
    assert section.ollama_url == "http://gpu:11434"
    assert section.anthropic_api_key == "sk-test"


def test_parse_allowlist_section() -> None:
    section = parse_allowlist({"path": ".wtfguardignore"})
    assert section.path == ".wtfguardignore"


def test_load_missing_returns_empty(tmp_path: Path) -> None:
    cfg = load(tmp_path / "absent.toml")
    assert cfg.scan.jobs is None
    assert cfg.llm.backend is None
    assert cfg.source is None


def test_load_full_config(tmp_path: Path) -> None:
    f = tmp_path / "wtfguard.toml"
    f.write_text(
        "[scan]\n"
        "jobs = 8\n"
        "no_llm = true\n"
        "\n"
        "[llm]\n"
        "backend = \"ollama\"\n"
        "model = \"qwen2.5-coder:32b\"\n"
        "\n"
        "[allowlist]\n"
        "path = \".wtfguardignore\"\n",
        encoding="utf-8",
    )
    cfg = load(f)
    assert cfg.scan.jobs == 8
    assert cfg.scan.no_llm is True
    assert cfg.llm.backend == "ollama"
    assert cfg.llm.model == "qwen2.5-coder:32b"
    assert cfg.allowlist.path == ".wtfguardignore"
    assert cfg.source == f


def test_load_malformed_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "bad.toml"
    f.write_text("this is not [[[ toml", encoding="utf-8")
    cfg = load(f)
    assert cfg.scan.jobs is None
    assert cfg.source is None


def test_discover_prefers_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit.toml"
    explicit.write_text("", encoding="utf-8")
    monkeypatch.setenv("WTFGUARD_CONFIG", str(explicit))
    monkeypatch.chdir(tmp_path)
    assert discover_path() == explicit


def test_discover_falls_back_to_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WTFGUARD_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    local = tmp_path / "wtfguard.toml"
    local.write_text("", encoding="utf-8")
    monkeypatch.setattr("wtfguard.config.DEFAULT_PATH", tmp_path / "absent.toml")
    assert discover_path() == local


def test_discover_returns_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WTFGUARD_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("wtfguard.config.DEFAULT_PATH", tmp_path / "absent.toml")
    assert discover_path() is None


def test_apply_to_env_sets_unset_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Clear any pre-set values from autouse fixture
    monkeypatch.delenv("WTFGUARD_LLM_BACKEND", raising=False)
    monkeypatch.delenv("WTFGUARD_LLM_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("WTFGUARD_OLLAMA_URL", raising=False)
    monkeypatch.delenv("WTFGUARD_ALLOWLIST", raising=False)

    from wtfguard.config import AllowlistSection, LlmSection, ScanSection
    cfg = Config(
        scan=ScanSection(),
        llm=LlmSection(backend="ollama", model="qwen2.5-coder:32b", ollama_url="http://gpu:11434"),
        allowlist=AllowlistSection(path=".wtfguardignore"),
    )
    apply_to_env(cfg)
    assert os.environ["WTFGUARD_LLM_BACKEND"] == "ollama"
    assert os.environ["WTFGUARD_LLM_MODEL"] == "qwen2.5-coder:32b"
    assert os.environ["WTFGUARD_OLLAMA_URL"] == "http://gpu:11434"
    assert os.environ["WTFGUARD_ALLOWLIST"] == ".wtfguardignore"


def test_apply_to_env_does_not_override_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WTFGUARD_LLM_BACKEND", "claude")
    from wtfguard.config import AllowlistSection, LlmSection, ScanSection
    cfg = Config(
        scan=ScanSection(),
        llm=LlmSection(backend="ollama"),
        allowlist=AllowlistSection(),
    )
    apply_to_env(cfg)
    assert os.environ["WTFGUARD_LLM_BACKEND"] == "claude"
