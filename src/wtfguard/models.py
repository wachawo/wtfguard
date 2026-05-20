#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dataclasses for findings, severity tiers, and verdicts."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.upper()]

    def label(self) -> str:
        return self.name.lower()


SEVERITY_BY_NAME: dict[str, Severity] = {s.name.lower(): s for s in Severity}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    snippet: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":     self.rule_id,
            "severity":    self.severity.label(),
            "file":        self.file,
            "line":        self.line,
            "snippet":     self.snippet,
            "description": self.description,
        }


@dataclass
class Verdict:
    package: str
    version: str
    severity: Severity
    confidence: float
    findings: list[Finding] = field(default_factory=list)
    diff_hash: str | None = None
    llm_explanation: str | None = None
    model: str | None = None
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "package":         self.package,
            "version":         self.version,
            "severity":        self.severity.label(),
            "confidence":      self.confidence,
            "findings":        [f.to_dict() for f in self.findings],
            "diff_hash":       self.diff_hash,
            "llm_explanation": self.llm_explanation,
            "model":           self.model,
            "scanned_at":      self.scanned_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def exit_code(self) -> int:
        if self.severity >= Severity.CRITICAL:
            return 2
        if self.severity >= Severity.HIGH:
            return 1
        return 0
