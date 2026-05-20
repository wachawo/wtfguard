#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regex- and AST-based heuristic detectors for suspicious code patterns."""

import ast
import logging
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


DEFAULT_RULES_PATH = Path(__file__).parent / "data" / "patterns.yaml"


def load_rules(yaml_path: Path | None = None, extra_paths: list[Path] | None = None) -> list[Rule]:
    """Load bundled patterns.yaml plus any extra YAML files of the same shape.

    Extra rules with an id that matches a bundled rule replace it — letting
    users tighten or relax built-in patterns. Extra rules with new ids are
    appended.
    """
    base_path = yaml_path or DEFAULT_RULES_PATH
    rules = read_rules_file(base_path)
    by_id: dict[str, Rule] = {r.id: r for r in rules}

    for extra in extra_paths or []:
        for rule in read_rules_file(extra):
            if rule.id in by_id:
                logger.info(f"Overriding rule {rule.id} from {extra}")
            by_id[rule.id] = rule

    return list(by_id.values())


def read_rules_file(yaml_path: Path) -> list[Rule]:
    if not yaml_path.is_file():
        logger.warning(f"Rules file missing: {yaml_path}")
        return []
    try:
        with yaml_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning(f"Cannot read rules {yaml_path}: {type(exc).__name__}: {exc}")
        return []

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
            logger.warning(f"Skipping invalid rule {entry.get('id', '?')} from {yaml_path.name}: {type(exc).__name__}: {exc}")
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


SUSPICIOUS_BUILD_BACKENDS = frozenset({"setuptools.build_meta:__legacy__"})
BUILD_HOOK_KEYS = ("hooks", "build-hooks", "pre-build", "post-build")


def scan_pyproject_toml(path: Path, content: str) -> list[Finding]:
    """TOML-aware checks for pyproject.toml.

    Catches suspicious build-backends, custom build hooks (hatch/pdm/poetry),
    and uncommon entry-points like `post_install`.
    """
    findings: list[Finding] = []
    if path.name != "pyproject.toml":
        return findings

    try:
        data: dict[str, Any] = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        logger.debug(f"TOML parse failed for {path}: {exc}")
        return findings

    build_system = data.get("build-system") or {}
    requires = build_system.get("requires") or []
    if isinstance(requires, list):
        for req in requires:
            if isinstance(req, str) and looks_like_url_or_path(req):
                findings.append(
                    Finding(
                        rule_id="BUILD_REQ_URL",
                        severity=Severity.HIGH,
                        file=str(path),
                        line=1,
                        snippet=req[:200],
                        description="build-system.requires references a URL or path — unusual for legitimate packages",
                    )
                )

    backend = build_system.get("build-backend")
    if isinstance(backend, str) and not is_known_build_backend(backend):
        findings.append(
            Finding(
                rule_id="UNKNOWN_BUILD_BACKEND",
                severity=Severity.LOW,
                file=str(path),
                line=1,
                snippet=backend[:200],
                description="Uncommon build-backend — review the backend module before installing",
            )
        )

    tool = data.get("tool") or {}
    findings.extend(scan_tool_section_for_hooks(path, tool))
    findings.extend(scan_entry_points(path, data.get("project") or {}))

    return findings


KNOWN_BUILD_BACKENDS = frozenset({
    "setuptools.build_meta",
    "flit_core.buildapi",
    "flit.buildapi",
    "poetry.core.masonry.api",
    "poetry.masonry.api",
    "hatchling.build",
    "pdm.backend",
    "pdm.pep517.api",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
})


def is_known_build_backend(backend: str) -> bool:
    head = backend.split(":", 1)[0]
    if head in KNOWN_BUILD_BACKENDS:
        return True
    return backend in SUSPICIOUS_BUILD_BACKENDS


def looks_like_url_or_path(req: str) -> bool:
    return any(prefix in req for prefix in ("http://", "https://", "git+", "file:", "/", "@ "))


def scan_tool_section_for_hooks(path: Path, tool: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for tool_name, section in tool.items():
        if not isinstance(section, dict):
            continue
        for key in BUILD_HOOK_KEYS:
            if key not in section:
                continue
            value = section[key]
            out.append(
                Finding(
                    rule_id="BUILD_HOOK",
                    severity=Severity.MEDIUM,
                    file=str(path),
                    line=1,
                    snippet=f"[tool.{tool_name}.{key}] = {str(value)[:160]}",
                    description=f"Custom build hook under [tool.{tool_name}.{key}] — runs at install/build time",
                )
            )
        if tool_name == "poetry":
            scripts = section.get("scripts") or {}
            if isinstance(scripts, dict):
                for script_name, target in scripts.items():
                    if isinstance(target, str) and "post_install" in script_name.lower():
                        out.append(
                            Finding(
                                rule_id="POETRY_POSTINSTALL",
                                severity=Severity.MEDIUM,
                                file=str(path),
                                line=1,
                                snippet=f"{script_name} -> {target}",
                                description="Poetry script named 'post_install*' — may run at install time",
                            )
                        )
    return out


def scan_entry_points(path: Path, project: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    entry_points = project.get("entry-points") or {}
    if not isinstance(entry_points, dict):
        return out
    for group, items in entry_points.items():
        if not isinstance(items, dict):
            continue
        if "install" in group.lower() or "post" in group.lower():
            for name, target in items.items():
                out.append(
                    Finding(
                        rule_id="ENTRY_POINT_INSTALL",
                        severity=Severity.MEDIUM,
                        file=str(path),
                        line=1,
                        snippet=f"[{group}] {name} = {target}",
                        description=f"Entry-point group '{group}' suggests install-time execution",
                    )
                )
    return out


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
        findings.extend(scan_pyproject_toml(Path(rel), content))

    return findings


def aggregate_severity(findings: list[Finding]) -> Severity:
    """Highest severity among findings, or CLEAN if empty."""
    if not findings:
        return Severity.CLEAN
    return max(f.severity for f in findings)
