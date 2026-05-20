#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the analyzer orchestrator (no network — pypi/llm are mocked)."""

from pathlib import Path
from unittest.mock import patch

from wtfguard import analyzer, heuristics
from wtfguard.llm import LlmVerdict
from wtfguard.models import Severity


def test_combine_severity_low_confidence_keeps_heuristic() -> None:
    sev, conf = analyzer.combine_severity(Severity.MEDIUM, 0.9, Severity.CRITICAL, 0.4)
    assert sev == Severity.MEDIUM
    assert conf == 0.9


def test_combine_severity_high_confidence_uses_max() -> None:
    sev, conf = analyzer.combine_severity(Severity.MEDIUM, 0.7, Severity.HIGH, 0.8)
    assert sev == Severity.HIGH
    assert conf == 0.7


def test_combine_severity_agreement_uses_higher_confidence() -> None:
    sev, conf = analyzer.combine_severity(Severity.HIGH, 0.7, Severity.HIGH, 0.9)
    assert sev == Severity.HIGH
    assert conf == 0.9


def test_analyze_snapshot_clean_package(safe_package: Path) -> None:
    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=False, use_cache=False)
    verdict = analyzer.analyze_snapshot("safe-pkg", "1.0.0", safe_package, rules, opts)
    assert verdict.severity == Severity.CLEAN
    assert verdict.findings == []
    assert verdict.confidence == 1.0


def test_analyze_snapshot_malicious_package(malicious_package: Path) -> None:
    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=False, use_cache=False)
    verdict = analyzer.analyze_snapshot("bad-pkg", "2.0.0", malicious_package, rules, opts)
    assert verdict.severity == Severity.CRITICAL
    assert verdict.findings


def test_analyze_snapshot_with_llm_high_confidence(malicious_package: Path) -> None:
    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=True, use_cache=False)
    fake = LlmVerdict(severity=Severity.CRITICAL, confidence=0.9, explanation="bad stuff", model="test-model")
    with patch("wtfguard.llm.audit_diff", return_value=fake):
        verdict = analyzer.analyze_snapshot("bad-pkg", "2.0.0", malicious_package, rules, opts)
    assert verdict.severity == Severity.CRITICAL
    assert verdict.llm_explanation == "bad stuff"
    assert verdict.model == "test-model"


def test_analyze_snapshot_llm_skipped_when_below_trigger(safe_package: Path) -> None:
    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=True, use_cache=False)
    with patch("wtfguard.llm.audit_diff") as mock_llm:
        verdict = analyzer.analyze_snapshot("safe-pkg", "1.0.0", safe_package, rules, opts)
    assert verdict.severity == Severity.CLEAN
    mock_llm.assert_not_called()


def test_analyze_snapshot_llm_unavailable_falls_back(malicious_package: Path) -> None:
    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=True, use_cache=False)
    with patch("wtfguard.llm.audit_diff", return_value=None):
        verdict = analyzer.analyze_snapshot("bad-pkg", "2.0.0", malicious_package, rules, opts)
    assert verdict.severity == Severity.CRITICAL
    assert verdict.llm_explanation is None


def test_analyze_diff_clean(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")
    (new / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")

    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=False, use_cache=False)
    verdict = analyzer.analyze_diff("x", "1.1.0", "1.0.0", old, new, rules, opts)
    assert verdict.severity == Severity.CLEAN
    assert verdict.diff_hash is not None
    assert len(verdict.diff_hash) == 64


def test_analyze_diff_uses_cache(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")
    (new / "setup.py").write_text("setup(name='y')\n", encoding="utf-8")

    rules = heuristics.load_rules()
    cache_path = tmp_path / "c.sqlite"
    opts = analyzer.AnalysisOptions(use_llm=False, use_cache=True, cache_path=cache_path)

    first = analyzer.analyze_diff("x", "1.1.0", "1.0.0", old, new, rules, opts)
    assert first.diff_hash is not None

    from wtfguard.cache import VerdictCache
    with VerdictCache(cache_path) as cache:
        cache.put(first)

    second = analyzer.analyze_diff("x", "1.1.0", "1.0.0", old, new, rules, opts)
    assert second.diff_hash == first.diff_hash


def test_analyze_diff_with_llm_consensus(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "setup.py").write_text("setup(name='x')\n", encoding="utf-8")
    (new / "setup.py").write_text(
        "import urllib\nurllib.urlopen('http://x')\nsetup(name='x')\n",
        encoding="utf-8",
    )

    rules = heuristics.load_rules()
    opts = analyzer.AnalysisOptions(use_llm=True, use_cache=False)
    fake = LlmVerdict(severity=Severity.HIGH, confidence=0.85, explanation="net call", model="m")
    with patch("wtfguard.llm.audit_diff", return_value=fake):
        verdict = analyzer.analyze_diff("x", "1.1.0", "1.0.0", old, new, rules, opts)
    assert verdict.severity == Severity.HIGH
    assert verdict.llm_explanation == "net call"


def test_render_snapshot_for_llm_returns_files(malicious_package: Path) -> None:
    rules = heuristics.load_rules()
    findings = heuristics.scan_directory(malicious_package, rules)
    rendered = analyzer.render_snapshot_for_llm(malicious_package, findings)
    assert "setup.py" in rendered
    assert "```" in rendered


def test_render_snapshot_empty_findings() -> None:
    assert analyzer.render_snapshot_for_llm(Path("/nonexistent"), []) == ""


def test_analyze_package_orchestrates_snapshot(malicious_package: Path, tmp_path: Path) -> None:
    from wtfguard.pypi import PackageRelease

    fake_release = PackageRelease(
        name="bad-pkg",
        version="2.0.0",
        files=[],
        summary=None,
        project_urls={},
    )

    def fake_fetch(name: str, version: str | None, workdir: Path) -> tuple[PackageRelease, Path]:
        return fake_release, malicious_package

    cache_path = tmp_path / "c.sqlite"
    opts = analyzer.AnalysisOptions(use_llm=False, use_cache=False, cache_path=cache_path, work_dir=tmp_path)
    with patch("wtfguard.pypi.fetch_and_extract", side_effect=fake_fetch):
        verdict = analyzer.analyze_package("bad-pkg", "2.0.0", None, opts)
    assert verdict.severity == Severity.CRITICAL


def test_analyze_package_with_base_version_runs_diff(safe_package: Path, malicious_package: Path, tmp_path: Path) -> None:
    from wtfguard.pypi import PackageRelease

    def fake_fetch(name: str, version: str | None, workdir: Path) -> tuple[PackageRelease, Path]:
        root = malicious_package if version != "1.0.0" else safe_package
        ver = version or "latest"
        return PackageRelease(name=name, version=ver, files=[], summary=None, project_urls={}), root

    opts = analyzer.AnalysisOptions(use_llm=False, use_cache=False, work_dir=tmp_path)
    with patch("wtfguard.pypi.fetch_and_extract", side_effect=fake_fetch):
        verdict = analyzer.analyze_package("pkg", "2.0.0", "1.0.0", opts)
    assert verdict.severity == Severity.CRITICAL
    assert verdict.diff_hash is not None
