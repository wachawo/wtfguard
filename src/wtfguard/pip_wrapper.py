#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pre-install hook: scan packages before delegating to the real pip.

Usage: `wtfguard pip install foo bar==1.2.3 -r reqs.txt`.

Behaviour:
- For pip subcommands other than `install`, delegate immediately without
  scanning (uninstall, freeze, list, show, etc.).
- For `install`, extract package specs (positional args and -r requirements
  files), scan each, and either block (critical) or warn (high/medium).
- After scanning succeeds — or the user confirms — exec the real pip.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from wtfguard import allowlist, analyzer, lockfile
from wtfguard.models import Severity, Verdict

logger = logging.getLogger(__name__)

NON_SCAN_SUBCOMMANDS = frozenset({
    "uninstall", "freeze", "list", "show", "search",
    "config", "cache", "wheel", "hash", "completion",
    "debug", "inspect", "help",
})


@dataclass(frozen=True)
class PipArgs:
    subcommand: str
    specs:      tuple[tuple[str, str | None], ...]
    raw:        tuple[str, ...]


def parse_pip_args(argv: list[str]) -> PipArgs:
    """Extract pip subcommand and package specs from argv.

    Skips flags (anything starting with `-`); -r and --requirement values
    are recognised so their referenced files can be read by the caller.
    """
    subcommand = ""
    for token in argv:
        if not token.startswith("-"):
            subcommand = token
            break

    specs: list[tuple[str, str | None]] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in ("-r", "--requirement") and i + 1 < len(argv):
            req_path = Path(argv[i + 1])
            if req_path.is_file():
                specs.extend(lockfile.parse_file(req_path))
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        if token == subcommand:
            i += 1
            continue
        name, version = split_spec(token)
        if name:
            specs.append((name, version))
        i += 1

    return PipArgs(subcommand=subcommand, specs=tuple(specs), raw=tuple(argv))


def split_spec(spec: str) -> tuple[str, str | None]:
    """Parse `foo`, `foo==1.0`, `foo>=1.0`, etc. Returns (name, version_or_none)."""
    cleaned = spec.split(";")[0].strip()
    if cleaned.startswith(("http://", "https://", "git+", "file://", ".", "/")):
        return "", None
    if "==" in cleaned:
        name, version = cleaned.split("==", 1)
        return name.strip().split("[")[0], version.strip()
    for marker in (">=", "<=", "~=", "!=", ">", "<"):
        if marker in cleaned:
            return cleaned.split(marker, 1)[0].strip().split("[")[0], None
    return cleaned.split("[")[0], None


def scan_specs(
    specs: Iterable[tuple[str, str | None]],
    options: analyzer.AnalysisOptions,
    allowlist_path: Path | None = None,
) -> tuple[list[Verdict], Severity, list[str]]:
    """Scan each spec, return (verdicts, worst_severity, allowlisted)."""
    rules = allowlist.load(allowlist_path)
    verdicts: list[Verdict] = []
    skipped: list[str] = []
    worst = Severity.CLEAN

    for name, version in specs:
        if rules.allows(name, version):
            skipped.append(f"{name}=={version or 'latest'}")
            continue
        try:
            verdict = analyzer.analyze_package(name, version, None, options)
        except LookupError as exc:
            logger.warning(f"Cannot scan {name}: {exc}")
            continue
        verdicts.append(verdict)
        worst = Severity(max(int(worst), int(verdict.severity)))

    return verdicts, worst, skipped


def delegate_to_pip(argv: list[str]) -> int:
    """Run `python -m pip <argv>` and return its exit code."""
    result = subprocess.run([sys.executable, "-m", "pip", *argv], check=False)
    return result.returncode


def should_skip_scan(parsed: PipArgs) -> bool:
    if parsed.subcommand == "" or parsed.subcommand in NON_SCAN_SUBCOMMANDS:
        return True
    return parsed.subcommand != "install"
