#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TOML config file loader for `~/.wtfguard/config.toml` and project-local overrides.

Lookup order (first match wins, values shallow-merge):
1. `WTFGUARD_CONFIG` env var (explicit file path)
2. `./wtfguard.toml` in the current working directory
3. `~/.wtfguard/config.toml`

Schema (all sections + keys optional):

    [scan]
    jobs = 8
    no_llm = false
    no_cache = false

    [llm]
    backend = "ollama"      # claude | ollama
    model = "qwen2.5-coder:32b"
    ollama_url = "http://gpu-host:11434"
    anthropic_api_key = "sk-ant-..."   # discouraged; prefer ANTHROPIC_API_KEY env

    [allowlist]
    path = ".wtfguardignore"

Env vars and CLI flags still win. Config is a way to set personal/team
defaults without typing them every time.
"""

from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ENV_VAR = "WTFGUARD_CONFIG"
LOCAL_NAME = "wtfguard.toml"
DEFAULT_PATH = Path.home() / ".wtfguard" / "config.toml"


@dataclass(frozen=True)
class ScanSection:
    jobs:     int | None = None
    no_llm:   bool | None = None
    no_cache: bool | None = None


@dataclass(frozen=True)
class LlmSection:
    backend:           str | None = None
    model:             str | None = None
    ollama_url:        str | None = None
    anthropic_api_key: str | None = None


@dataclass(frozen=True)
class AllowlistSection:
    path: str | None = None


@dataclass(frozen=True)
class Config:
    scan:      ScanSection = field(default_factory=ScanSection)
    llm:       LlmSection = field(default_factory=LlmSection)
    allowlist: AllowlistSection = field(default_factory=AllowlistSection)
    source:    Path | None = None


def discover_path(start_dir: Path | None = None) -> Path | None:
    env_value = os.getenv(ENV_VAR)
    if env_value:
        env_path = Path(env_value)
        if env_path.is_file():
            return env_path

    local = (start_dir or Path.cwd()) / LOCAL_NAME
    if local.is_file():
        return local

    if DEFAULT_PATH.is_file():
        return DEFAULT_PATH

    return None


def load(path: Path | None = None) -> Config:
    """Read a config file. Returns an empty Config if nothing is found or readable."""
    resolved = path or discover_path()
    if resolved is None:
        return Config()

    try:
        data = tomllib.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.warning(f"Cannot parse {resolved}: {type(exc).__name__}: {exc}")
        return Config()

    return Config(
        scan=parse_scan(data.get("scan") or {}),
        llm=parse_llm(data.get("llm") or {}),
        allowlist=parse_allowlist(data.get("allowlist") or {}),
        source=resolved,
    )


def parse_scan(data: dict[str, Any]) -> ScanSection:
    return ScanSection(
        jobs=int(data["jobs"]) if isinstance(data.get("jobs"), int) else None,
        no_llm=bool(data.get("no_llm")) if "no_llm" in data else None,
        no_cache=bool(data.get("no_cache")) if "no_cache" in data else None,
    )


def parse_llm(data: dict[str, Any]) -> LlmSection:
    return LlmSection(
        backend=string_or_none(data.get("backend")),
        model=string_or_none(data.get("model")),
        ollama_url=string_or_none(data.get("ollama_url")),
        anthropic_api_key=string_or_none(data.get("anthropic_api_key")),
    )


def parse_allowlist(data: dict[str, Any]) -> AllowlistSection:
    return AllowlistSection(path=string_or_none(data.get("path")))


def string_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def apply_to_env(config: Config) -> None:
    """Project config values into env vars only if the env var isn't already set.

    This means an explicitly-exported env var or a CLI flag still wins over
    config — config is the default, env/CLI are overrides.
    """
    if config.llm.backend and "WTFGUARD_LLM_BACKEND" not in os.environ:
        os.environ["WTFGUARD_LLM_BACKEND"] = config.llm.backend
    if config.llm.model and "WTFGUARD_LLM_MODEL" not in os.environ:
        os.environ["WTFGUARD_LLM_MODEL"] = config.llm.model
    if config.llm.ollama_url and "WTFGUARD_OLLAMA_URL" not in os.environ:
        os.environ["WTFGUARD_OLLAMA_URL"] = config.llm.ollama_url
    if config.llm.anthropic_api_key and "ANTHROPIC_API_KEY" not in os.environ:
        os.environ["ANTHROPIC_API_KEY"] = config.llm.anthropic_api_key
    if config.allowlist.path and "WTFGUARD_ALLOWLIST" not in os.environ:
        os.environ["WTFGUARD_ALLOWLIST"] = config.allowlist.path
