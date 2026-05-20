#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the click CLI (no network — analyzer is mocked)."""

import json
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
