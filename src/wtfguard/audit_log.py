#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append-only JSONL audit log of every scan wtfguard runs.

Compliance frameworks (SOC2, ISO 27001) want an unbroken paper trail of
"who scanned what, when, and what was the verdict". This module provides
the minimum viable trail: one JSON line per scan, never mutated, easy to
rotate.

Default location: `~/.wtfguard/audit.log.jsonl`. Override via
`WTFGUARD_AUDIT_LOG` env or `[audit].path` in config.toml (Phase 2).
Set `WTFGUARD_AUDIT_DISABLED=1` to skip logging entirely.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from wtfguard.models import Verdict

logger = logging.getLogger(__name__)

ENV_PATH = "WTFGUARD_AUDIT_LOG"
ENV_DISABLE = "WTFGUARD_AUDIT_DISABLED"
DEFAULT_PATH = Path.home() / ".wtfguard" / "audit.log.jsonl"
TRUE_VALUES = ("1", "true", "yes", "on")


def is_enabled() -> bool:
    return os.getenv(ENV_DISABLE, "").lower() not in TRUE_VALUES


def resolve_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    override = os.getenv(ENV_PATH)
    if override:
        return Path(override)
    return DEFAULT_PATH


def append_entry(entry: dict[str, Any], path: Path | None = None) -> None:
    """Write one JSON object as a single line. No-op if disabled."""
    if not is_enabled():
        return
    target = resolve_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    try:
        with target.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        logger.warning(f"Cannot write audit log {target}: {type(exc).__name__}: {exc}")


def log_verdict(verdict: Verdict, command: str = "scan", path: Path | None = None) -> None:
    """Convenience: project a Verdict into a flat audit-log entry."""
    rule_ids = sorted({f.rule_id for f in verdict.findings})
    entry = {
        "timestamp":      now_iso(),
        "command":        command,
        "package":        verdict.package,
        "version":        verdict.version,
        "severity":       verdict.severity.label(),
        "confidence":     verdict.confidence,
        "findings_count": len(verdict.findings),
        "rule_ids":       rule_ids,
        "diff_hash":      verdict.diff_hash,
        "model":          verdict.model,
    }
    append_entry(entry, path)


def log_batch(verdicts: Iterable[Verdict], command: str = "scan-requirements", path: Path | None = None) -> None:
    """Log a single line per verdict in a batch run."""
    for v in verdicts:
        log_verdict(v, command=command, path=path)


def read_entries(path: Path | None = None) -> list[dict[str, Any]]:
    """Parse every JSON line of the audit log. Malformed lines are skipped."""
    target = resolve_path(path)
    if not target.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for raw in target.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
    except OSError as exc:
        logger.warning(f"Cannot read audit log {target}: {type(exc).__name__}: {exc}")
    return out


def prune_older_than(days: int, path: Path | None = None) -> int:
    """Drop entries older than `days` days. Returns the number of entries removed."""
    target = resolve_path(path)
    if not target.is_file():
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=days)
    kept: list[str] = []
    removed = 0
    try:
        for raw in target.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                kept.append(raw)
                continue
            ts_raw = parsed.get("timestamp") if isinstance(parsed, dict) else None
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts < cutoff:
                        removed += 1
                        continue
                except ValueError:
                    pass
            kept.append(raw)
        target.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    except OSError as exc:
        logger.warning(f"Cannot prune audit log {target}: {type(exc).__name__}: {exc}")
    return removed


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
