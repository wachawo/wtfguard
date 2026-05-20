#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sanity-check the wtfguard installation.

`wtfguard self-test` enumerates everything that has to be working for a
full scan and reports each as pass / warn / fail. Aimed at:
- first-time users wondering "did I install this right?"
- compliance teams who want a documented "we ran the verification" step
- CI bootstrap where you want to fail fast before the first real scan.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wtfguard import __version__, heuristics, llm, system_env

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckResult:
    name:     str
    status:   str   # "pass" | "warn" | "fail"
    detail:   str

    def is_failure(self) -> bool:
        return self.status == "fail"


@dataclass
class SelfTestReport:
    checks: list[CheckResult]

    @property
    def passes(self) -> int:
        return sum(1 for c in self.checks if c.status == "pass")

    @property
    def warns(self) -> int:
        return sum(1 for c in self.checks if c.status == "warn")

    @property
    def fails(self) -> int:
        return sum(1 for c in self.checks if c.status == "fail")

    def to_dict(self) -> dict[str, Any]:
        return {
            "passes": self.passes,
            "warns":  self.warns,
            "fails":  self.fails,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail}
                for c in self.checks
            ],
        }


def run_all() -> SelfTestReport:
    return SelfTestReport(checks=[
        check_python_version(),
        check_wtfguard_version(),
        check_virtualenv(),
        check_pep668(),
        check_heuristics_loadable(),
        check_state_dir_writable(),
        check_llm_backend(),
    ])


def check_python_version() -> CheckResult:
    version = sys.version_info
    label = f"{version.major}.{version.minor}.{version.micro}"
    if version < (3, 11):
        return CheckResult("python_version", "fail", f"{label} (need >=3.11)")
    return CheckResult("python_version", "pass", label)


def check_wtfguard_version() -> CheckResult:
    return CheckResult("wtfguard_version", "pass", __version__)


def check_virtualenv() -> CheckResult:
    if system_env.is_in_virtualenv():
        return CheckResult("virtualenv", "pass", f"prefix={sys.prefix}")
    return CheckResult("virtualenv", "warn", f"running outside a venv (prefix={sys.prefix})")


def check_pep668() -> CheckResult:
    marker = system_env.externally_managed_marker()
    if marker is None:
        return CheckResult("pep668", "pass", "no EXTERNALLY-MANAGED marker")
    if system_env.is_in_virtualenv():
        return CheckResult("pep668", "pass", f"system marker present ({marker}) but inside venv")
    return CheckResult("pep668", "warn", f"system Python is externally managed: {marker}")


def check_heuristics_loadable() -> CheckResult:
    try:
        rules = heuristics.load_rules()
    except Exception as exc:
        return CheckResult("heuristics", "fail", f"{type(exc).__name__}: {exc}")
    if not rules:
        return CheckResult("heuristics", "fail", "no rules loaded from bundled patterns.yaml")
    return CheckResult("heuristics", "pass", f"{len(rules)} rules loaded")


def check_state_dir_writable() -> CheckResult:
    state_dir = Path.home() / ".wtfguard"
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        probe = state_dir / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return CheckResult("state_dir", "pass", str(state_dir))
    except OSError as exc:
        return CheckResult("state_dir", "fail", f"{state_dir}: {type(exc).__name__}: {exc}")


def check_llm_backend() -> CheckResult:
    backend = llm.active_backend()
    if backend is None:
        return CheckResult("llm_backend", "warn",
                           "no backend reachable (set ANTHROPIC_API_KEY or start Ollama for LLM stage)")
    return CheckResult("llm_backend", "pass", f"active: {backend}")


def format_text(report: SelfTestReport) -> str:
    lines = ["wtfguard self-test", ""]
    glyph = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}
    for c in report.checks:
        lines.append(f"  {glyph.get(c.status, '[????]')}  {c.name:20}  {c.detail}")
    lines.append("")
    lines.append(f"summary: {report.passes} pass, {report.warns} warn, {report.fails} fail")
    return "\n".join(lines)
