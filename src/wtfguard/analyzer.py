#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Top-level orchestrator: heuristics + optional LLM → final Verdict."""

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from wtfguard import advisory, diff, heuristics, llm, pypi, pypi_signals, typosquat
from wtfguard.cache import VerdictCache
from wtfguard.models import Finding, Severity, Verdict

logger = logging.getLogger(__name__)

LLM_TRIGGER_SEVERITY = Severity.MEDIUM
LLM_CONFIDENCE_FLOOR = 0.6
DEFAULT_HEURISTIC_CONFIDENCE = 0.9


@dataclass
class AnalysisOptions:
    use_llm:        bool = True
    use_cache:      bool = True
    use_advisory:   bool = True
    use_metadata:   bool = True
    use_typosquat:  bool = True
    cache_path:     Path | None = None
    work_dir:       Path | None = None
    extra_rules:    list[Path] | None = None


def analyze_package(
    name: str,
    version: str | None = None,
    base_version: str | None = None,
    options: AnalysisOptions | None = None,
) -> Verdict:
    """Scan a single PyPI package.

    If base_version is given, runs a version-to-version diff scan.
    Otherwise, scans the single release in isolation.
    """
    opts = options or AnalysisOptions()
    work_dir = opts.work_dir or Path(tempfile.mkdtemp(prefix="wtfguard-"))

    new_release, new_root = pypi.fetch_and_extract(name, version, work_dir / "new")
    rules = heuristics.load_rules(extra_paths=opts.extra_rules)

    if base_version is None:
        verdict = analyze_snapshot(name, new_release.version, new_root, rules, opts)
    else:
        old_release, old_root = pypi.fetch_and_extract(name, base_version, work_dir / "old")
        verdict = analyze_diff(name, new_release.version, old_release.version, old_root, new_root, rules, opts)

    if opts.use_cache and verdict.diff_hash is not None:
        with VerdictCache(opts.cache_path) as cache:
            cache.put(verdict)

    return verdict


def analyze_snapshot(
    name: str,
    version: str,
    root: Path,
    rules: list[heuristics.Rule],
    opts: AnalysisOptions,
) -> Verdict:
    findings = heuristics.scan_directory(root, rules)
    if opts.use_advisory:
        findings.extend(advisory.to_findings(advisory.lookup(name, version)))
    if opts.use_metadata:
        findings.extend(pypi_signals.signals_for(name))
    if opts.use_typosquat:
        findings.extend(typosquat.check(name))
    severity = heuristics.aggregate_severity(findings)
    confidence = DEFAULT_HEURISTIC_CONFIDENCE if findings else 1.0

    diff_text = ""
    diff_h: str | None = None

    if opts.use_llm and severity >= LLM_TRIGGER_SEVERITY:
        diff_text = render_snapshot_for_llm(root, findings)
        llm_verdict = llm.audit_diff(name, version, diff_text, rules)
        if llm_verdict is not None:
            severity, confidence = combine_severity(severity, confidence, llm_verdict.severity, llm_verdict.confidence)
            return Verdict(
                package=name,
                version=version,
                severity=severity,
                confidence=confidence,
                findings=findings,
                diff_hash=diff_h,
                llm_explanation=llm_verdict.explanation,
                model=llm_verdict.model,
            )

    return Verdict(
        package=name,
        version=version,
        severity=severity,
        confidence=confidence,
        findings=findings,
        diff_hash=diff_h,
    )


def analyze_diff(
    name: str,
    new_version: str,
    old_version: str,
    old_root: Path,
    new_root: Path,
    rules: list[heuristics.Rule],
    opts: AnalysisOptions,
) -> Verdict:
    diffs = diff.tree_diff(old_root, new_root)
    meaningful = diff.meaningful_diffs(diffs)
    diff_h = diff.diff_hash(diffs)

    if opts.use_cache:
        with VerdictCache(opts.cache_path) as cache:
            cached = cache.get(diff_h)
            if cached is not None:
                logger.info(f"Cache hit for {name} {old_version}->{new_version} (hash={diff_h[:12]})")
                return cached

    findings = heuristics.scan_directory(new_root, rules)
    if opts.use_advisory:
        findings.extend(advisory.to_findings(advisory.lookup(name, new_version)))
    if opts.use_metadata:
        findings.extend(pypi_signals.signals_for(name))
    if opts.use_typosquat:
        findings.extend(typosquat.check(name))
    severity = heuristics.aggregate_severity(findings)
    confidence = DEFAULT_HEURISTIC_CONFIDENCE if findings else 1.0
    llm_explanation: str | None = None
    model: str | None = None

    if opts.use_llm and (severity >= LLM_TRIGGER_SEVERITY or meaningful):
        diff_text = "\n".join(d.body for d in meaningful if d.body)
        if diff_text:
            llm_verdict = llm.audit_diff(name, new_version, diff_text, rules)
            if llm_verdict is not None:
                severity, confidence = combine_severity(severity, confidence, llm_verdict.severity, llm_verdict.confidence)
                llm_explanation = llm_verdict.explanation
                model = llm_verdict.model

    return Verdict(
        package=name,
        version=new_version,
        severity=severity,
        confidence=confidence,
        findings=findings,
        diff_hash=diff_h,
        llm_explanation=llm_explanation,
        model=model,
    )


def combine_severity(
    heur_sev: Severity,
    heur_conf: float,
    llm_sev: Severity,
    llm_conf: float,
) -> tuple[Severity, float]:
    """Combine heuristic and LLM severities.

    Rules:
    - If LLM is confident (>=0.6), use max(heur, llm).
    - If LLM is not confident (<0.6), trust heuristic only.
    - Final confidence is the higher of the two contributing scores when they agree,
      otherwise the lower (we are less sure when signals disagree).
    """
    if llm_conf < LLM_CONFIDENCE_FLOOR:
        return heur_sev, heur_conf

    final_sev = Severity(max(int(heur_sev), int(llm_sev)))
    final_conf = max(heur_conf, llm_conf) if heur_sev == llm_sev else min(heur_conf, llm_conf)
    return final_sev, final_conf


def render_snapshot_for_llm(root: Path, findings: list[Finding]) -> str:
    """For snapshot mode, send the LLM only the files that triggered findings, not the whole tree."""
    files = sorted({f.file for f in findings})
    if not files:
        return ""

    blocks: list[str] = []
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning(f"Cannot read {path}: {type(exc).__name__}: {exc}")
            continue
        blocks.append(f"### {rel}\n```\n{content[:20000]}\n```")
    return "\n\n".join(blocks)
