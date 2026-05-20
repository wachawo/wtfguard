#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the pip pre-install wrapper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from wtfguard.analyzer import AnalysisOptions
from wtfguard.models import Severity, Verdict
from wtfguard.pip_wrapper import (
    PipArgs,
    delegate_to_pip,
    parse_pip_args,
    scan_specs,
    should_skip_scan,
    split_spec,
)


def make_verdict(severity: Severity = Severity.CLEAN) -> Verdict:
    return Verdict(package="demo", version="1.0.0", severity=severity, confidence=0.9)


def test_split_spec_exact() -> None:
    assert split_spec("requests==2.32.0") == ("requests", "2.32.0")


def test_split_spec_bare() -> None:
    assert split_spec("requests") == ("requests", None)


def test_split_spec_inequality() -> None:
    assert split_spec("requests>=2.0") == ("requests", None)
    assert split_spec("numpy~=1.26") == ("numpy", None)


def test_split_spec_with_extras() -> None:
    assert split_spec("requests[socks]==2.32.0") == ("requests", "2.32.0")
    assert split_spec("requests[socks]") == ("requests", None)


def test_split_spec_url_returns_empty() -> None:
    assert split_spec("https://example/foo.whl") == ("", None)
    assert split_spec("git+https://example/foo") == ("", None)
    assert split_spec("./local-pkg") == ("", None)


def test_split_spec_environment_marker() -> None:
    assert split_spec("requests==2.32.0; python_version > '3.8'") == ("requests", "2.32.0")


def test_parse_pip_args_install_with_specs() -> None:
    parsed = parse_pip_args(["install", "requests==2.32.0", "numpy", "--upgrade"])
    assert parsed.subcommand == "install"
    assert ("requests", "2.32.0") in parsed.specs
    assert ("numpy", None) in parsed.specs


def test_parse_pip_args_install_with_requirements_file(tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("requests==2.32.0\nnumpy==1.26.0\n", encoding="utf-8")
    parsed = parse_pip_args(["install", "-r", str(req)])
    names = {n for n, _ in parsed.specs}
    assert names == {"requests", "numpy"}


def test_parse_pip_args_install_with_long_requirement_flag(tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("requests==2.32.0\n", encoding="utf-8")
    parsed = parse_pip_args(["install", "--requirement", str(req)])
    assert ("requests", "2.32.0") in parsed.specs


def test_parse_pip_args_uninstall() -> None:
    parsed = parse_pip_args(["uninstall", "-y", "requests"])
    assert parsed.subcommand == "uninstall"


def test_parse_pip_args_empty() -> None:
    parsed = parse_pip_args([])
    assert parsed.subcommand == ""
    assert parsed.specs == ()


def test_should_skip_scan_non_install() -> None:
    for cmd in ("uninstall", "list", "freeze", "show", "config"):
        assert should_skip_scan(PipArgs(subcommand=cmd, specs=(), raw=())) is True


def test_should_skip_scan_install_returns_false() -> None:
    assert should_skip_scan(PipArgs(subcommand="install", specs=(), raw=())) is False


def test_should_skip_scan_empty() -> None:
    assert should_skip_scan(PipArgs(subcommand="", specs=(), raw=())) is True


def test_scan_specs_filters_allowlisted(tmp_path: Path) -> None:
    allow = tmp_path / "ignore"
    allow.write_text("foo\n", encoding="utf-8")

    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(name)
        return make_verdict()

    options = AnalysisOptions(use_llm=False, use_cache=False)
    with patch("wtfguard.pip_wrapper.analyzer.analyze_package", side_effect=fake_analyze):
        result = scan_specs(
            [("foo", "1.0"), ("bar", "2.0")],
            options,
            allowlist_path=allow,
        )

    assert seen == ["bar"]
    assert "foo==1.0" in result[2]
    assert result[1] == Severity.CLEAN
    assert len(result[0]) == 1


def test_scan_specs_tracks_worst_severity() -> None:
    def fake_analyze(name, version, base_version, options):
        return make_verdict(Severity.CRITICAL if name == "bar" else Severity.CLEAN)

    options = AnalysisOptions(use_llm=False, use_cache=False)
    with patch("wtfguard.pip_wrapper.analyzer.analyze_package", side_effect=fake_analyze):
        _, worst, _ = scan_specs([("foo", "1.0"), ("bar", "2.0")], options)

    assert worst == Severity.CRITICAL


def test_scan_specs_skips_lookup_errors() -> None:
    def fake_analyze(name, version, base_version, options):
        if name == "ghost":
            raise LookupError("not on PyPI")
        return make_verdict()

    options = AnalysisOptions(use_llm=False, use_cache=False)
    with patch("wtfguard.pip_wrapper.analyzer.analyze_package", side_effect=fake_analyze):
        verdicts, worst, _ = scan_specs([("ghost", None), ("good", "1.0")], options)

    assert len(verdicts) == 1
    assert worst == Severity.CLEAN


def test_delegate_to_pip_invokes_subprocess() -> None:
    fake_result = MagicMock()
    fake_result.returncode = 0
    with patch("wtfguard.pip_wrapper.subprocess.run", return_value=fake_result) as mock_run:
        exit_code = delegate_to_pip(["install", "requests"])
    assert exit_code == 0
    args, _kwargs = mock_run.call_args
    assert args[0][-2:] == ["install", "requests"]
    assert "pip" in args[0]
