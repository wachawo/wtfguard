#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regex- and AST-based heuristic detectors for suspicious code patterns."""

import ast
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from wtfguard.models import Finding, Severity

logger = logging.getLogger(__name__)

INSTALL_SCRIPT_NAMES = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "MANIFEST.in"})
SCAN_EXTENSIONS = frozenset({".py", ".pyi", ".cfg", ".toml", ".txt"})


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    description: str
    file_scope: str
    regex: re.Pattern[str]

    def applies_to(self, path: Path) -> bool:
        if self.file_scope == "any":
            return True
        if self.file_scope == "install_script":
            return path.name in INSTALL_SCRIPT_NAMES
        return False


def load_rules(yaml_path: Path | None = None) -> list[Rule]:
    """Load heuristic rules from the bundled patterns.yaml (or a custom path)."""
    if yaml_path is None:
        yaml_path = Path(__file__).parent / "data" / "patterns.yaml"

    with yaml_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    rules: list[Rule] = []
    for entry in raw.get("rules", []):
        try:
            rules.append(
                Rule(
                    id=entry["id"],
                    severity=Severity.from_name(entry["severity"]),
                    description=entry["description"],
                    file_scope=entry.get("file_scope", "any"),
                    regex=re.compile(entry["regex"]),
                )
            )
        except (KeyError, re.error) as exc:
            logger.warning(f"Skipping invalid rule {entry.get('id', '?')}: {type(exc).__name__}: {exc}")
    return rules


def scan_text(path: Path, content: str, rules: Iterable[Rule]) -> list[Finding]:
    """Run all applicable regex rules against a file's text content."""
    findings: list[Finding] = []
    lines = content.splitlines()
    for rule in rules:
        if not rule.applies_to(path):
            continue
        for match in rule.regex.finditer(content):
            line_no = content.count("\n", 0, match.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else match.group(0)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    file=str(path),
                    line=line_no,
                    snippet=snippet[:200],
                    description=rule.description,
                )
            )
    return findings


def scan_ast_setup_py(path: Path, content: str) -> list[Finding]:
    """AST-level checks specific to setup.py.

    Catches things regex misses: e.g. setuptools.setup(..., cmdclass={"install": Custom})
    where Custom.run() does something malicious.
    """
    findings: list[Finding] = []
    if path.name != "setup.py":
        return findings

    try:
        tree = ast.parse(content, filename=str(path))
    except SyntaxError as exc:
        logger.debug(f"AST parse failed for {path}: {exc}")
        return findings

    has_custom_cmdclass = False
    custom_classes: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_setup_call = (
            (isinstance(node.func, ast.Attribute) and node.func.attr == "setup")
            or (isinstance(node.func, ast.Name) and node.func.id == "setup")
        )
        if not is_setup_call:
            continue
        for kw in node.keywords:
            if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                has_custom_cmdclass = True
                for value in kw.value.values:
                    if isinstance(value, ast.Name):
                        custom_classes.add(value.id)

    if has_custom_cmdclass:
        findings.append(
            Finding(
                rule_id="CUSTOM_CMDCLASS",
                severity=Severity.MEDIUM,
                file=str(path),
                line=1,
                snippet=f"cmdclass overrides: {sorted(custom_classes)}",
                description="setup.py overrides install/build commands via cmdclass — review carefully",
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name in custom_classes:
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in {
                    "system",
                    "popen",
                    "call",
                    "Popen",
                    "run",
                    "check_call",
                    "check_output",
                }:
                    findings.append(
                        Finding(
                            rule_id="CMDCLASS_SUBPROCESS",
                            severity=Severity.HIGH,
                            file=str(path),
                            line=child.lineno,
                            snippet=ast.unparse(child)[:200],
                            description=f"Custom cmdclass {node.name} runs subprocess — possible install-time payload",
                        )
                    )

    return findings


def scan_directory(root: Path, rules: list[Rule]) -> list[Finding]:
    """Walk a directory and apply heuristics to every relevant file."""
    findings: list[Finding] = []
    if not root.exists():
        return findings

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in SCAN_EXTENSIONS and path.name not in INSTALL_SCRIPT_NAMES:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning(f"Cannot read {path}: {type(exc).__name__}: {exc}")
            continue

        rel = path.relative_to(root) if path.is_relative_to(root) else path
        findings.extend(scan_text(Path(rel), content, rules))
        findings.extend(scan_ast_setup_py(Path(rel), content))

    return findings


def aggregate_severity(findings: list[Finding]) -> Severity:
    """Highest severity among findings, or CLEAN if empty."""
    if not findings:
        return Severity.CLEAN
    return max(f.severity for f in findings)
