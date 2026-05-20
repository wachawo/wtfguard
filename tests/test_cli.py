#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the click CLI (no network — analyzer is mocked)."""

import json
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from wtfguard import cli, state
from wtfguard.models import Finding, Severity, Verdict


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ~/.wtfguard/ to a tmp dir so tests do not pollute the real cache."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("wtfguard.state.DEFAULT_STATE_PATH", home / ".wtfguard" / "state.json")
    monkeypatch.setattr("wtfguard.cache.DEFAULT_CACHE_PATH", home / ".wtfguard" / "cache.sqlite")
    return home


def make_verdict(severity: Severity = Severity.CLEAN) -> Verdict:
    finding = Finding(
        rule_id="NET_IN_SETUP",
        severity=Severity.HIGH,
        file="setup.py",
        line=1,
        snippet="urlopen(...)",
        description="Network call in setup.py",
    )
    return Verdict(
        package="demo",
        version="1.0.0",
        severity=severity,
        confidence=0.85,
        findings=[finding] if severity >= Severity.HIGH else [],
        diff_hash="hash" if severity != Severity.CLEAN else None,
    )


def test_help_lists_all_commands(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["--help"])
    assert result.exit_code == 0
    for cmd in ("scan", "scan-requirements", "achievements", "tip", "doctor"):
        assert cmd in result.output


def test_version(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["--version"])
    assert result.exit_code == 0
    assert "wtfguard" in result.output


def test_no_subcommand_prints_help(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, [])
    assert result.exit_code == 0
    assert "Usage" in result.output


def test_tip_command(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["tip"])
    assert result.exit_code == 0
    assert result.output.strip()


def test_doctor_command(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["doctor"])
    assert result.exit_code == 0
    assert "version" in result.output
    assert "backend" in result.output


def test_achievements_empty(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["achievements"])
    assert result.exit_code == 0
    assert "scans:0" in result.output


def test_achievements_with_unlocks(runner: CliRunner, isolated_home: Path) -> None:
    s = state.State(skips_total=12, achievements=["skip-10"])
    state.save_state(s)
    result = runner.invoke(cli.main, ["achievements"])
    assert result.exit_code == 0
    assert "Speed Reader" in result.output
    assert "unlocked" in result.output


def test_scan_clean_package(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["scan", "demo==1.0.0"])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_scan_high_severity_exits_1(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.HIGH)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["scan", "demo==1.0.0"])
    assert result.exit_code == 1
    assert "HIGH" in result.output


def test_scan_critical_severity_exits_2(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CRITICAL)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["scan", "demo==1.0.0"])
    assert result.exit_code == 2


def test_scan_json_output(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["scan", "demo==1.0.0", "--json"])
    assert result.exit_code == 0
    # Output is JSON object on stdout
    payload = json.loads(result.output)
    assert payload["package"] == "demo"
    assert payload["severity"] == "clean"


def test_scan_package_not_found(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.analyzer.analyze_package", side_effect=LookupError("nope")):
        result = runner.invoke(cli.main, ["scan", "ghost"])
    assert result.exit_code == 1
    assert "error" in result.output


def test_scan_internal_error(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.analyzer.analyze_package", side_effect=RuntimeError("boom")):
        result = runner.invoke(cli.main, ["scan", "demo"])
    assert result.exit_code == 1
    assert "internal error" in result.output


def test_scan_with_base_version_flag(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    captured = {}

    def fake_analyze(name, version, base_version, options):
        captured["name"] = name
        captured["version"] = version
        captured["base"] = base_version
        return verdict

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan", "demo==2.0.0", "--base", "1.0.0"])
    assert result.exit_code == 0
    assert captured["base"] == "1.0.0"
    assert captured["version"] == "2.0.0"


def test_scan_no_llm_flag_propagates(runner: CliRunner, isolated_home: Path) -> None:
    captured = {}

    def fake_analyze(name, version, base_version, options):
        captured["use_llm"] = options.use_llm
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        runner.invoke(cli.main, ["scan", "demo", "--no-llm"])
    assert captured["use_llm"] is False


def test_scan_increments_scan_counter(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.analyzer.analyze_package", return_value=make_verdict(Severity.CLEAN)):
        runner.invoke(cli.main, ["scan", "demo"])
        runner.invoke(cli.main, ["scan", "demo"])
    loaded = state.load_state()
    assert loaded.scans_total == 2


def test_scan_requirements_empty_file(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("# comment only\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["scan-requirements", str(req)])
    assert result.exit_code == 0
    assert "no packages" in result.output


def test_scan_requirements_runs_for_each_pkg(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("foo==1.0.0\nbar==2.0.0\n", encoding="utf-8")

    calls: list[str] = []

    def fake_analyze(name, version, base_version, options):
        calls.append(f"{name}=={version}")
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(req)])
    assert result.exit_code == 0
    assert calls == ["foo==1.0.0", "bar==2.0.0"]


def test_scan_requirements_worst_severity_determines_exit(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("foo==1.0.0\nbar==2.0.0\n", encoding="utf-8")

    def fake_analyze(name, version, base_version, options):
        return make_verdict(Severity.CRITICAL if name == "bar" else Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(req)])
    assert result.exit_code == 2


def test_scan_requirements_skips_lookup_error(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("foo==1.0.0\nbar==2.0.0\n", encoding="utf-8")

    def fake_analyze(name, version, base_version, options):
        if name == "foo":
            raise LookupError("not found")
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(req)])
    assert "skip" in result.output


def test_parse_package_spec_with_version() -> None:
    assert cli.parse_package_spec("foo==1.2.3") == ("foo", "1.2.3")


def test_parse_package_spec_without_version() -> None:
    assert cli.parse_package_spec("foo") == ("foo", None)


def test_parse_requirements_file_filters_comments(tmp_path: Path) -> None:
    f = tmp_path / "req.txt"
    f.write_text(
        "# top comment\n"
        "foo==1.0  # pinned\n"
        "\n"
        "bar==2.0; python_version > '3.8'\n"
        "baz\n"
        "-e .\n",
        encoding="utf-8",
    )
    result = cli.parse_requirements_file(f)
    assert ("foo", "1.0") in result
    assert ("bar", "2.0") in result
    assert ("baz", None) in result
    assert len(result) == 3


def test_pick_talkative_silent_wins() -> None:
    assert cli.pick_talkative(state_value=True, flag=True, silent=True) is False


def test_pick_talkative_explicit_flag_overrides_state() -> None:
    assert cli.pick_talkative(state_value=False, flag=True, silent=False) is True
    assert cli.pick_talkative(state_value=True, flag=False, silent=False) is False


def test_pick_talkative_env_var_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WTFGUARD_TALKATIVE", "1")
    assert cli.pick_talkative(state_value=False, flag=None, silent=False) is True


def test_pick_talkative_falls_back_to_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WTFGUARD_TALKATIVE", raising=False)
    assert cli.pick_talkative(state_value=True, flag=None, silent=False) is True
    assert cli.pick_talkative(state_value=False, flag=None, silent=False) is False


def test_apply_achievements_unlocks_and_persists(isolated_home: Path) -> None:
    s = state.State(skips_total=10)
    cli.apply_achievements(s)
    assert "skip-10" in s.achievements


def test_secret_reveal_disables_talkative(isolated_home: Path) -> None:
    s = state.State(skips_total=1000, talkative=True)
    with patch("wtfguard.cli.time.sleep"):
        cli.apply_achievements(s)
    assert "skip-1000" in s.achievements
    assert s.talkative is False


def test_scan_talkative_flag_starts_streamer(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.tips.TipStreamer") as mock_streamer_cls:
        result = runner.invoke(cli.main, ["scan", "demo", "--talkative"])
    assert result.exit_code == 0
    mock_streamer_cls.assert_called_once()


def test_scan_json_does_not_start_streamer(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.tips.TipStreamer") as mock_streamer_cls:
        runner.invoke(cli.main, ["scan", "demo", "--talkative", "--json"])
    mock_streamer_cls.assert_not_called()


def test_scan_allowlisted_skips_analyzer(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    allow = tmp_path / "ignore"
    allow.write_text("demo\n", encoding="utf-8")
    with patch("wtfguard.analyzer.analyze_package") as mock_analyze:
        result = runner.invoke(cli.main, ["scan", "demo==1.0.0", "--allowlist", str(allow)])
    assert result.exit_code == 0
    assert "allowlisted" in result.output
    mock_analyze.assert_not_called()


def test_scan_requirements_allowlist_skips_some(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("foo==1.0\nbar==2.0\n", encoding="utf-8")
    allow = tmp_path / "ignore"
    allow.write_text("foo\n", encoding="utf-8")

    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(name)
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(req), "--allowlist", str(allow)])
    assert result.exit_code == 0
    assert seen == ["bar"]
    assert "allowlisted" in result.output


def test_scan_installed_runs_for_each_pkg(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.installed import InstalledPackage

    pkgs = [InstalledPackage(name="alpha", version="1.0"), InstalledPackage(name="beta", version="2.0")]
    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(f"{name}=={version}")
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-installed"])
    assert result.exit_code == 0
    assert seen == ["alpha==1.0", "beta==2.0"]


def test_scan_installed_empty_env(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.installed.list_installed", return_value=[]):
        result = runner.invoke(cli.main, ["scan-installed"])
    assert result.exit_code == 0
    assert "no installed packages" in result.output


def test_scan_installed_max_packages(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.installed import InstalledPackage

    pkgs = [InstalledPackage(name=f"p{i}", version="1.0") for i in range(5)]
    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(name)
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-installed", "--max-packages", "2"])
    assert result.exit_code == 0
    assert len(seen) == 2


def test_scan_installed_worst_severity_drives_exit(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.installed import InstalledPackage

    pkgs = [InstalledPackage(name="alpha", version="1.0"), InstalledPackage(name="beta", version="2.0")]

    def fake_analyze(name, version, base_version, options):
        return make_verdict(Severity.CRITICAL if name == "beta" else Severity.CLEAN)

    with patch("wtfguard.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-installed"])
    assert result.exit_code == 2


def test_scan_installed_with_allowlist(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    from wtfguard.installed import InstalledPackage

    allow = tmp_path / "ignore"
    allow.write_text("alpha\n", encoding="utf-8")
    pkgs = [InstalledPackage(name="alpha", version="1.0"), InstalledPackage(name="beta", version="2.0")]
    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(name)
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-installed", "--allowlist", str(allow)])
    assert result.exit_code == 0
    assert seen == ["beta"]


def test_scan_requirements_poetry_lock_autodetects(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    f = tmp_path / "poetry.lock"
    f.write_text(
        "[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n\n"
        "[[package]]\nname = \"numpy\"\nversion = \"1.26.0\"\n",
        encoding="utf-8",
    )

    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(f"{name}=={version}")
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(f)])
    assert result.exit_code == 0
    assert seen == ["requests==2.32.0", "numpy==1.26.0"]


def test_scan_requirements_pipfile_lock_autodetects(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    f = tmp_path / "Pipfile.lock"
    f.write_text(
        '{"default": {"requests": {"version": "==2.32.0"}}}',
        encoding="utf-8",
    )

    seen: list[str] = []

    def fake_analyze(name, version, base_version, options):
        seen.append(name)
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(f)])
    assert result.exit_code == 0
    assert seen == ["requests"]


def test_scan_requirements_json_output(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("foo==1.0\nbar==2.0\n", encoding="utf-8")

    def fake_analyze(name, version, base_version, options):
        sev = Severity.HIGH if name == "bar" else Severity.CLEAN
        return make_verdict(sev)

    with patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-requirements", str(req), "--json"])
    assert result.exit_code == 1  # high triggers exit 1
    payload = json.loads(result.output)
    assert "verdicts" in payload
    assert "worst" in payload
    assert payload["worst"] == "high"
    assert len(payload["verdicts"]) == 2


def test_scan_installed_json_output(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.installed import InstalledPackage

    pkgs = [InstalledPackage(name="alpha", version="1.0")]
    with patch("wtfguard.installed.list_installed", return_value=pkgs), \
         patch("wtfguard.analyzer.analyze_package", return_value=make_verdict(Severity.CLEAN)):
        result = runner.invoke(cli.main, ["scan-installed", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["worst"] == "clean"
    assert len(payload["verdicts"]) == 1


def test_verify_matching_cache_exits_0(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.cache import VerdictCache

    verdict = make_verdict(Severity.HIGH)
    verdict.diff_hash = "stable123"

    # Pre-populate the cache so verify sees a match
    with VerdictCache() as cache:
        cache.put(verdict)

    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["verify", "demo==1.0.0"])
    assert result.exit_code == 0
    assert "matches" in result.output.lower()


def test_verify_mismatch_exits_1(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.cache import VerdictCache

    cached_verdict = make_verdict(Severity.HIGH)
    cached_verdict.diff_hash = "stable123"
    fresh_verdict = make_verdict(Severity.CRITICAL)
    fresh_verdict.diff_hash = "stable123"

    with VerdictCache() as cache:
        cache.put(cached_verdict)

    with patch("wtfguard.analyzer.analyze_package", return_value=fresh_verdict):
        result = runner.invoke(cli.main, ["verify", "demo==1.0.0"])
    assert result.exit_code == 1
    assert "MISMATCH" in result.output


def test_verify_no_cache_exits_0(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.HIGH)
    verdict.diff_hash = "fresh-hash"
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["verify", "demo==1.0.0"])
    assert result.exit_code == 0
    assert "no cache" in result.output.lower()


def test_verify_no_diff_hash_exits_0(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    verdict.diff_hash = None
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        result = runner.invoke(cli.main, ["verify", "demo"])
    assert result.exit_code == 0


def test_verify_lookup_error_exits_2(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.analyzer.analyze_package", side_effect=LookupError("missing")):
        result = runner.invoke(cli.main, ["verify", "ghost==1.0"])
    assert result.exit_code == 2


def test_bench_text_format(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["bench"])
    assert result.exit_code == 0
    assert "true positives" in result.output


def test_bench_markdown_format(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["bench", "--format", "markdown"])
    assert result.exit_code == 0
    assert result.output.startswith("# wtfguard heuristic benchmark")


def test_bench_json_format(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["bench", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "totals" in payload
    assert "rule_activations" in payload


def test_rules_text(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["rules"])
    assert result.exit_code == 0
    assert "NET_IN_SETUP" in result.output


def test_rules_json(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["rules", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert any(r["id"] == "NET_IN_SETUP" for r in payload)
    assert all("regex" in r for r in payload)


def test_init_creates_starter_files(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    result = runner.invoke(cli.main, ["init", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "wtfguard.toml").is_file()
    assert (tmp_path / ".wtfguardignore").is_file()
    assert "[scan]" in (tmp_path / "wtfguard.toml").read_text(encoding="utf-8")


def test_init_skips_existing_without_force(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    (tmp_path / "wtfguard.toml").write_text("# user content\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["init", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "skipped" in result.output
    assert (tmp_path / "wtfguard.toml").read_text(encoding="utf-8") == "# user content\n"


def test_init_force_overwrites(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    (tmp_path / "wtfguard.toml").write_text("# old\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["init", "--dir", str(tmp_path), "--force"])
    assert result.exit_code == 0
    assert "[scan]" in (tmp_path / "wtfguard.toml").read_text(encoding="utf-8")


def test_pip_install_clean_delegates(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CLEAN)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.pip_wrapper.delegate_to_pip", return_value=0) as mock_delegate:
        result = runner.invoke(cli.main, ["pip", "install", "requests==2.32.0"])
    assert result.exit_code == 0
    mock_delegate.assert_called_once()


def test_pip_install_critical_blocks(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.CRITICAL)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.pip_wrapper.delegate_to_pip") as mock_delegate:
        result = runner.invoke(cli.main, ["pip", "install", "evil==1.0"])
    assert result.exit_code == 2
    assert "BLOCKED" in result.output
    mock_delegate.assert_not_called()


def test_pip_install_high_requires_confirm(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.HIGH)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.pip_wrapper.delegate_to_pip", return_value=0) as mock_delegate:
        # User says "no" — abort
        result = runner.invoke(cli.main, ["pip", "install", "risky"], input="n\n")
    assert result.exit_code == 1
    mock_delegate.assert_not_called()


def test_pip_install_high_yes_skips_confirm(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.HIGH)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.pip_wrapper.delegate_to_pip", return_value=0) as mock_delegate:
        result = runner.invoke(cli.main, ["pip", "install", "risky", "--yes"])
    assert result.exit_code == 0
    mock_delegate.assert_called_once()


def test_pip_uninstall_bypasses_scan(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.analyzer.analyze_package") as mock_analyze, \
         patch("wtfguard.pip_wrapper.delegate_to_pip", return_value=0) as mock_delegate:
        result = runner.invoke(cli.main, ["pip", "uninstall", "-y", "requests"])
    assert result.exit_code == 0
    mock_analyze.assert_not_called()
    mock_delegate.assert_called_once()


def test_pip_install_fail_on_medium(runner: CliRunner, isolated_home: Path) -> None:
    verdict = make_verdict(Severity.MEDIUM)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict), \
         patch("wtfguard.pip_wrapper.delegate_to_pip") as mock_delegate:
        result = runner.invoke(cli.main, ["pip", "install", "x", "--fail-on", "medium"])
    assert result.exit_code == 2
    mock_delegate.assert_not_called()


def test_pip_install_no_specs(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.pip_wrapper.delegate_to_pip", return_value=0) as mock_delegate:
        result = runner.invoke(cli.main, ["pip", "install", "--upgrade-strategy", "eager"])
    assert result.exit_code == 0
    mock_delegate.assert_called_once()


def test_scan_dir_clean(runner: CliRunner, isolated_home: Path, safe_package: Path) -> None:
    result = runner.invoke(cli.main, ["scan-dir", str(safe_package)])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_scan_dir_critical_exits_2(runner: CliRunner, isolated_home: Path, malicious_package: Path) -> None:
    result = runner.invoke(cli.main, ["scan-dir", str(malicious_package)])
    assert result.exit_code == 2


def test_scan_dir_json_output(runner: CliRunner, isolated_home: Path, safe_package: Path) -> None:
    result = runner.invoke(cli.main, ["scan-dir", str(safe_package), "--json", "--name", "my-pkg"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["package"] == "my-pkg"
    assert payload["severity"] == "clean"


def test_bench_network_no_packages(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.bench.fetch_top_packages", return_value=[]):
        result = runner.invoke(cli.main, ["bench", "--network", "--top", "5"])
    assert result.exit_code == 0  # 0 flagged_high


def test_bench_network_finds_flagged(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.bench import NetworkBenchmarkReport
    from wtfguard.models import Verdict

    flagged = Verdict(package="bar", version="1.0", severity=Severity.HIGH, confidence=0.9)
    fake_report = NetworkBenchmarkReport(verdicts=[flagged])
    with patch("wtfguard.bench.run_network_benchmark", return_value=fake_report):
        result = runner.invoke(cli.main, ["bench", "--network", "--top", "1"])
    assert result.exit_code == 1
    assert "HIGH+ findings" in result.output


def test_bench_network_json_output(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.bench import NetworkBenchmarkReport

    fake_report = NetworkBenchmarkReport(verdicts=[], failed_packages=["ghost"])
    with patch("wtfguard.bench.run_network_benchmark", return_value=fake_report):
        result = runner.invoke(cli.main, ["bench", "--network", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["scanned"] == 0
    assert "ghost" in payload["failed"]


def test_audit_log_show_empty(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["audit-log", "show"])
    assert result.exit_code == 0
    assert "no matching" in result.output


def test_audit_log_show_recent_entries(runner: CliRunner, isolated_home: Path) -> None:
    # Run a scan to populate the audit log
    from wtfguard.models import Verdict
    verdict = Verdict(package="demo", version="1.0", severity=Severity.LOW, confidence=1.0)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        runner.invoke(cli.main, ["scan", "demo==1.0"])

    result = runner.invoke(cli.main, ["audit-log", "show"])
    assert result.exit_code == 0
    assert "demo" in result.output


def test_audit_log_show_severity_filter(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.models import Verdict
    high = Verdict(package="bad", version="1.0", severity=Severity.HIGH, confidence=0.8)
    clean = Verdict(package="ok", version="1.0", severity=Severity.CLEAN, confidence=1.0)
    with patch("wtfguard.analyzer.analyze_package", side_effect=[high, clean]):
        runner.invoke(cli.main, ["scan", "bad==1.0"])
        runner.invoke(cli.main, ["scan", "ok==1.0"])

    result = runner.invoke(cli.main, ["audit-log", "show", "--severity", "high"])
    assert result.exit_code == 0
    assert "bad" in result.output
    assert "ok" not in result.output


def test_audit_log_show_json(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.models import Verdict
    verdict = Verdict(package="demo", version="1.0", severity=Severity.LOW, confidence=1.0)
    with patch("wtfguard.analyzer.analyze_package", return_value=verdict):
        runner.invoke(cli.main, ["scan", "demo==1.0"])

    result = runner.invoke(cli.main, ["audit-log", "show", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)


def test_audit_log_prune_with_yes(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["audit-log", "prune", "--days", "30", "--yes"])
    assert result.exit_code == 0
    assert "removed" in result.output


def test_audit_log_prune_declined(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["audit-log", "prune", "--days", "30"], input="n\n")
    assert result.exit_code == 0
    assert "aborted" in result.output


def test_audit_log_stats_empty(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["audit-log", "stats"])
    assert result.exit_code == 0
    assert "total entries" in result.output


def test_audit_log_stats_with_entries(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.models import Verdict
    high = Verdict(package="bad", version="1.0", severity=Severity.HIGH, confidence=0.9)
    low = Verdict(package="ok", version="1.0", severity=Severity.LOW, confidence=1.0)
    with patch("wtfguard.analyzer.analyze_package", side_effect=[high, low]):
        runner.invoke(cli.main, ["scan", "bad==1.0"])
        runner.invoke(cli.main, ["scan", "ok==1.0"])

    result = runner.invoke(cli.main, ["audit-log", "stats"])
    assert result.exit_code == 0
    assert "by severity" in result.output
    assert "by command" in result.output


def test_audit_log_stats_json(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["audit-log", "stats", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "total" in payload
    assert "by_severity" in payload


def test_refresh_popular_dry_run(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.bench.fetch_top_packages", return_value=["requests", "numpy"]):
        result = runner.invoke(cli.main, ["refresh-popular", "--dry-run", "--top", "2"])
    assert result.exit_code == 0
    assert "requests" in result.output


def test_refresh_popular_writes_file(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    target = tmp_path / "p.txt"
    with patch("wtfguard.bench.fetch_top_packages", return_value=["requests", "numpy"]):
        result = runner.invoke(cli.main, ["refresh-popular", "--output", str(target), "--top", "2"])
    assert result.exit_code == 0
    assert "wrote 2 names" in result.output
    assert "requests" in target.read_text(encoding="utf-8")


def test_refresh_popular_network_failure(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.bench.fetch_top_packages", return_value=[]):
        result = runner.invoke(cli.main, ["refresh-popular"])
    assert result.exit_code == 1
    assert "could not fetch" in result.output


def test_pre_commit_config_basic(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["pre-commit-config"])
    assert result.exit_code == 0
    assert "wtfguard-scan-dir" in result.output
    assert "wtfguard-scan-requirements" not in result.output


def test_pre_commit_config_with_requirements(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["pre-commit-config", "--include-requirements"])
    assert result.exit_code == 0
    assert "wtfguard-scan-dir" in result.output
    assert "wtfguard-scan-requirements" in result.output


def test_cache_stats_no_files(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["cache", "stats"])
    assert result.exit_code == 0
    assert "verdict cache" in result.output


def test_cache_stats_json(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["cache", "stats", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "verdict_cache" in payload
    assert "advisory_cache" in payload
    assert "metadata_cache" in payload


def test_cache_clear_no_flags(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["cache", "clear"])
    assert result.exit_code == 1
    assert "nothing to clear" in result.output


def test_cache_clear_advisory_only(runner: CliRunner, isolated_home: Path) -> None:
    # Create a fake advisory cache file under the isolated home
    advisory_path = isolated_home / ".wtfguard" / "advisory-cache.json"
    advisory_path.parent.mkdir(parents=True, exist_ok=True)
    advisory_path.write_text("{}", encoding="utf-8")

    # Patch Path.home() so the CLI looks in our tmp dir
    with patch("wtfguard.cli.Path.home", return_value=isolated_home):
        result = runner.invoke(cli.main, ["cache", "clear", "--advisory", "--yes"])
    assert result.exit_code == 0
    assert not advisory_path.exists()


def test_cache_clear_declined(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["cache", "clear", "--all"], input="n\n")
    assert result.exit_code == 0
    assert "aborted" in result.output


def test_config_show(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["config", "show"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "llm" in result.output
    assert "env vars" in result.output


def test_config_show_json(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["config", "show", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "scan" in payload
    assert "llm" in payload
    assert "env" in payload


def test_scan_tree_tree_only(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.dependency_tree import TreeNode

    fake_tree = TreeNode("demo", "1.0", 0, children=[TreeNode("dep", "2.0", 1)])
    with patch("wtfguard.dependency_tree.resolve_tree", return_value=fake_tree):
        result = runner.invoke(cli.main, ["scan-tree", "demo==1.0", "--tree-only"])
    assert result.exit_code == 0
    assert "demo==1.0" in result.output
    assert "dep==2.0" in result.output


def test_scan_tree_tree_only_json(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.dependency_tree import TreeNode

    fake_tree = TreeNode("demo", "1.0", 0)
    with patch("wtfguard.dependency_tree.resolve_tree", return_value=fake_tree):
        result = runner.invoke(cli.main, ["scan-tree", "demo==1.0", "--tree-only", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["name"] == "demo"


def test_scan_tree_scans_resolved_nodes(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.dependency_tree import TreeNode

    fake_tree = TreeNode("demo", "1.0", 0, children=[TreeNode("dep_a", "2.0", 1)])
    seen: list[str] = []

    def fake_analyze(name, version, base, options):
        seen.append(name)
        return make_verdict(Severity.CLEAN)

    with patch("wtfguard.dependency_tree.resolve_tree", return_value=fake_tree), \
         patch("wtfguard.analyzer.analyze_package", side_effect=fake_analyze):
        result = runner.invoke(cli.main, ["scan-tree", "demo==1.0"])
    assert result.exit_code == 0
    assert "demo" in seen
    assert "dep_a" in seen


def test_show_includes_attestation_status(runner: CliRunner, isolated_home: Path) -> None:
    from datetime import datetime

    from wtfguard.pypi_signals import PackageMetadata

    meta = PackageMetadata(
        name="demo",
        latest_version="1.0.0",
        summary="",
        project_urls={},
        release_count=5,
        first_release_at=datetime(2024, 1, 1, tzinfo=UTC),
        last_release_at=datetime(2025, 1, 1, tzinfo=UTC),
        latest_file_count=3,
        has_attestations=True,
        attestation_count=3,
    )
    with patch("wtfguard.pypi_signals.fetch_metadata", return_value=meta):
        result = runner.invoke(cli.main, ["show", "demo"])
    assert result.exit_code == 0
    assert "PEP 740" in result.output
    assert "yes" in result.output


def test_incident_no_events(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.incident.pypi_signals.pull_pypi_metadata", return_value=None):
        result = runner.invoke(cli.main, ["incident", "ghost"])
    assert result.exit_code == 0
    assert "no events" in result.output


def test_incident_json(runner: CliRunner, isolated_home: Path) -> None:
    from wtfguard.incident import IncidentReport
    with patch("wtfguard.incident.build_report", return_value=IncidentReport(package="demo", events=[])):
        result = runner.invoke(cli.main, ["incident", "demo", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["package"] == "demo"


def test_prefetch_empty_file(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("# only comments\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["prefetch", str(req)])
    assert result.exit_code == 0
    assert "succeeded: 0" in result.output


def test_prefetch_json(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    req = tmp_path / "req.txt"
    req.write_text("# empty\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["prefetch", str(req), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total"] == 0


def test_policy_cli_show_empty(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["policy-cli", "show"])
    assert result.exit_code == 0
    assert "overrides" in result.output


def test_policy_cli_show_loaded(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text(
        "overrides:\n"
        "  - rule: NET_IN_SETUP\n    severity: low\n    packages: [acme-internal]\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli.main, ["policy-cli", "show", str(f)])
    assert result.exit_code == 0
    assert "NET_IN_SETUP" in result.output


def test_policy_cli_validate_unknown_rule(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text("overrides:\n  - rule: TOTALLY_FAKE\n    severity: low\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["policy-cli", "validate", str(f)])
    assert result.exit_code == 1
    assert "unknown rule ids" in result.output


def test_policy_cli_validate_known_rule(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text("overrides:\n  - rule: NET_IN_SETUP\n    severity: low\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["policy-cli", "validate", str(f)])
    assert result.exit_code == 0
    assert "policy is valid" in result.output


def test_policy_cli_validate_empty(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    f = tmp_path / "policy.yaml"
    f.write_text("overrides: []\n", encoding="utf-8")
    result = runner.invoke(cli.main, ["policy-cli", "validate", str(f)])
    assert result.exit_code == 0
    assert "empty" in result.output


def test_show_json_includes_attestation_fields(runner: CliRunner, isolated_home: Path) -> None:
    from datetime import datetime

    from wtfguard.pypi_signals import PackageMetadata

    meta = PackageMetadata(
        name="demo", latest_version="1.0.0", summary="", project_urls={},
        release_count=1,
        first_release_at=datetime(2024, 1, 1, tzinfo=UTC),
        last_release_at=datetime(2024, 1, 1, tzinfo=UTC),
        latest_file_count=1,
        has_attestations=False,
        attestation_count=0,
    )
    with patch("wtfguard.pypi_signals.fetch_metadata", return_value=meta):
        result = runner.invoke(cli.main, ["show", "demo", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["has_attestations"] is False
    assert payload["attestation_count"] == 0


def test_explain_known_rule(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["explain", "NET_IN_SETUP"])
    assert result.exit_code == 0
    assert "NET_IN_SETUP" in result.output
    assert "Severity" in result.output
    assert "Pattern" in result.output


def test_explain_unknown_rule(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["explain", "DOES_NOT_EXIST"])
    assert result.exit_code == 1
    assert "no rule" in result.output


def test_explain_case_insensitive(runner: CliRunner, isolated_home: Path) -> None:
    result = runner.invoke(cli.main, ["explain", "net_in_setup"])
    assert result.exit_code == 0
    assert "NET_IN_SETUP" in result.output


def test_explain_loads_extra_rules(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    rules_file = tmp_path / "extra.yaml"
    rules_file.write_text(
        "rules:\n  - id: TEAM_X_RULE\n    severity: medium\n"
        "    description: Our internal pattern\n    regex: 'team_x_marker'\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli.main, ["explain", "TEAM_X_RULE", "--rules", str(rules_file)])
    assert result.exit_code == 0
    assert "TEAM_X_RULE" in result.output
    assert "team_x_marker" in result.output


def test_show_known_package(runner: CliRunner, isolated_home: Path) -> None:
    from datetime import datetime

    from wtfguard.pypi_signals import PackageMetadata

    meta = PackageMetadata(
        name="demo",
        latest_version="1.0.0",
        summary="A demo package",
        project_urls={"Homepage": "https://demo.example"},
        release_count=15,
        first_release_at=datetime(2023, 1, 1, tzinfo=UTC),
        last_release_at=datetime(2025, 1, 1, tzinfo=UTC),
        latest_file_count=8,
    )
    with patch("wtfguard.pypi_signals.fetch_metadata", return_value=meta):
        result = runner.invoke(cli.main, ["show", "demo"])
    assert result.exit_code == 0
    assert "demo" in result.output
    assert "1.0.0" in result.output
    assert "Homepage" in result.output


def test_show_not_found(runner: CliRunner, isolated_home: Path) -> None:
    with patch("wtfguard.pypi_signals.fetch_metadata", return_value=None):
        result = runner.invoke(cli.main, ["show", "ghost"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_show_json_format(runner: CliRunner, isolated_home: Path) -> None:
    from datetime import datetime

    from wtfguard.pypi_signals import PackageMetadata

    meta = PackageMetadata(
        name="demo",
        latest_version="1.0.0",
        summary="A demo",
        project_urls={},
        release_count=1,
        first_release_at=datetime(2026, 5, 1, tzinfo=UTC),
        last_release_at=datetime(2026, 5, 1, tzinfo=UTC),
        latest_file_count=1,
    )
    with patch("wtfguard.pypi_signals.fetch_metadata", return_value=meta):
        result = runner.invoke(cli.main, ["show", "demo", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["name"] == "demo"
    assert payload["latest_version"] == "1.0.0"
    assert "signals" in payload
    assert "advisories" in payload


def test_show_includes_metadata_signals_in_output(runner: CliRunner, isolated_home: Path) -> None:
    from datetime import datetime

    from wtfguard.pypi_signals import PackageMetadata

    # Single release + missing URLs + single file → multiple LOW signals
    meta = PackageMetadata(
        name="suspicious",
        latest_version="0.0.1",
        summary="",
        project_urls={},
        release_count=1,
        first_release_at=datetime(2026, 5, 18, tzinfo=UTC),
        last_release_at=datetime(2026, 5, 18, tzinfo=UTC),
        latest_file_count=1,
    )
    with patch("wtfguard.pypi_signals.fetch_metadata", return_value=meta):
        result = runner.invoke(cli.main, ["show", "suspicious"])
    assert result.exit_code == 0
    assert "LOW_RELEASE_COUNT" in result.output
    assert "MISSING_PROJECT_URL" in result.output


def test_rules_extra_yaml_listed(runner: CliRunner, isolated_home: Path, tmp_path: Path) -> None:
    rules_file = tmp_path / "extra.yaml"
    rules_file.write_text(
        "rules:\n  - id: TEAM_RULE\n    severity: high\n"
        "    description: x\n    regex: 'y'\n",
        encoding="utf-8",
    )
    result = runner.invoke(cli.main, ["rules", "--rules", str(rules_file)])
    assert result.exit_code == 0
    assert "TEAM_RULE" in result.output
