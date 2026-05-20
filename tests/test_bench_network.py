#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the bench --network shadow run."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from wtfguard.bench import (
    NetworkBenchmarkReport,
    fetch_top_packages,
    format_network_text,
    run_network_benchmark,
)
from wtfguard.models import Severity, Verdict


def make_verdict(name: str, severity: Severity = Severity.CLEAN) -> Verdict:
    return Verdict(package=name, version="1.0", severity=severity, confidence=1.0)


def fake_response(payload: object, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.raise_for_status = MagicMock()
    resp.json.return_value = payload
    return resp


def test_fetch_top_packages_parses_rows() -> None:
    payload = {"rows": [
        {"project": "requests", "download_count": 1000},
        {"project": "numpy", "download_count": 900},
        {"project": "pandas", "download_count": 800},
    ]}
    with patch("wtfguard.bench.requests.get", return_value=fake_response(payload)):
        names = fetch_top_packages(2)
    assert names == ["requests", "numpy"]


def test_fetch_top_packages_handles_alt_field_name() -> None:
    payload = {"rows": [{"name": "requests"}]}
    with patch("wtfguard.bench.requests.get", return_value=fake_response(payload)):
        names = fetch_top_packages(5)
    assert names == ["requests"]


def test_fetch_top_packages_network_error_returns_empty() -> None:
    import requests as r
    with patch("wtfguard.bench.requests.get", side_effect=r.ConnectionError("flap")):
        assert fetch_top_packages(5) == []


def test_fetch_top_packages_malformed_payload() -> None:
    with patch("wtfguard.bench.requests.get", return_value=fake_response("not a dict")):
        assert fetch_top_packages(5) == []


def test_run_network_benchmark_empty_top_returns_empty() -> None:
    with patch("wtfguard.bench.fetch_top_packages", return_value=[]):
        report = run_network_benchmark(top=10)
    assert report.total == 0


def test_run_network_benchmark_explicit_names(tmp_path: Path) -> None:
    def fake_analyze(name, version, base, options):
        return make_verdict(name, Severity.CLEAN)

    with patch("wtfguard.bench.analyzer.analyze_package", side_effect=fake_analyze):
        report = run_network_benchmark(fetch_top=["requests", "numpy"], work_dir=tmp_path)
    assert report.total == 2
    assert {v.package for v in report.verdicts} == {"requests", "numpy"}


def test_run_network_benchmark_captures_failed_packages(tmp_path: Path) -> None:
    def fake_analyze(name, version, base, options):
        if name == "ghost":
            raise LookupError("not on PyPI")
        return make_verdict(name, Severity.CLEAN)

    with patch("wtfguard.bench.analyzer.analyze_package", side_effect=fake_analyze):
        report = run_network_benchmark(fetch_top=["requests", "ghost"], work_dir=tmp_path)
    assert report.total == 1
    assert report.failed_packages == ["ghost"]


def test_network_report_fp_rate(tmp_path: Path) -> None:
    def fake_analyze(name, version, base, options):
        sev = Severity.HIGH if name == "bar" else Severity.CLEAN
        return make_verdict(name, sev)

    with patch("wtfguard.bench.analyzer.analyze_package", side_effect=fake_analyze):
        report = run_network_benchmark(fetch_top=["foo", "bar", "baz", "qux"], work_dir=tmp_path)
    assert report.flagged_high == 1
    assert report.fp_rate_high == 0.25


def test_format_network_text_includes_metrics(tmp_path: Path) -> None:
    report = NetworkBenchmarkReport(verdicts=[make_verdict("foo")])
    output = format_network_text(report)
    assert "scanned" in output
    assert "flagged high+" in output


def test_format_network_text_lists_flagged(tmp_path: Path) -> None:
    flagged = make_verdict("bar", Severity.HIGH)
    report = NetworkBenchmarkReport(verdicts=[make_verdict("foo"), flagged])
    output = format_network_text(report)
    assert "bar" in output
    assert "HIGH+ findings" in output


def test_format_network_text_truncates_failed_list() -> None:
    report = NetworkBenchmarkReport(
        verdicts=[],
        failed_packages=[f"pkg-{i}" for i in range(15)],
    )
    output = format_network_text(report)
    assert "(+5 more)" in output
