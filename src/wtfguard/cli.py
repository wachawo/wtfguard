#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wtfguard command-line interface."""

import json
import logging
import os
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wtfguard import (
    __version__,
    achievements,
    advisory,
    allowlist,
    analyzer,
    audit_log,
    bench,
    concurrency,
    config,
    cyclonedx,
    dependency_tree,
    heuristics,
    html_report,
    incident,
    installed,
    llm,
    lockfile,
    markdown_report,
    pip_wrapper,
    policy,
    prefetch,
    pypi_signals,
    sarif,
    sbom_merge,
    scan_dir,
    schemas,
    self_test,
    state,
    system_env,
    threats,
    tips,
    typosquat,
    verdict_diff,
    watch,
    webhook,
)
from wtfguard import (
    baseline as baseline_mod,
)
from wtfguard.cache import VerdictCache
from wtfguard.models import Severity, Verdict

LOG_FORMAT = "%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s) %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
logger = logging.getLogger(__name__)

TRUE_VALUES = ("1", "true", "yes", "on", "enabled")

SEVERITY_COLOR = {
    Severity.CLEAN:    "green",
    Severity.LOW:      "blue",
    Severity.MEDIUM:   "yellow",
    Severity.HIGH:     "orange3",
    Severity.CRITICAL: "red",
}

console = Console(stderr=False)


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.version_option(__version__, prog_name="wtfguard")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """wtfguard — semantic LLM audit for supply-chain attacks."""
    logging.basicConfig(
        format=LOG_FORMAT,
        datefmt=LOG_DATEFMT,
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stderr,
    )

    config.apply_to_env(config.load())

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.argument("package_spec")
@click.option("--base", "base_version", default=None, help="Diff against this installed version")
@click.option("--no-llm", is_flag=True, help="Disable LLM stage even when ANTHROPIC_API_KEY is set")
@click.option("--no-cache", is_flag=True, help="Bypass local verdict cache")
@click.option("--talkative", "talkative_flag", is_flag=True, default=None, help="Stream security tips during scan")
@click.option("--silent", "silent_flag", is_flag=True, default=None, help="Suppress tips even if state.talkative is on")
@click.option("--json", "json_output", is_flag=True, help="Emit verdict as JSON")
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None,
              help="Path to allowlist file (default: auto-discover)")
def scan(
    package_spec: str,
    base_version: str | None,
    no_llm: bool,
    no_cache: bool,
    talkative_flag: bool | None,
    silent_flag: bool | None,
    json_output: bool,
    allowlist_path: Path | None,
) -> None:
    """Scan a PyPI package. PACKAGE_SPEC can be `requests` or `requests==2.32.0`."""
    name, version = parse_package_spec(package_spec)
    user_state = state.load_state()
    talkative = pick_talkative(user_state.talkative, talkative_flag, silent_flag)

    allowlist_rules = allowlist.load(allowlist_path)
    if allowlist_rules.allows(name, version):
        console.print(f"[dim]allowlisted[/dim] {name}=={version or 'latest'} — skipping scan")
        sys.exit(0)

    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)

    streamer: tips.TipStreamer | None = None
    if talkative and not json_output:
        streamer = tips.TipStreamer(tips=tips.load_tips(), on_tip=lambda t: print_tip(t), interval=4.0)
        streamer.start()

    try:
        verdict = analyzer.analyze_package(name, version, base_version, options)
    except LookupError as exc:
        console.print(f"[red]error:[/red] {exc}")
        sys.exit(1)
    except Exception as exc:
        import traceback
        logger.error(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        console.print(f"[red]internal error:[/red] {type(exc).__name__}: {exc}")
        sys.exit(1)
    finally:
        if streamer is not None:
            streamer.stop()

    user_state.scans_total += 1
    apply_achievements(user_state)
    state.save_state(user_state)

    if json_output:
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    else:
        render_verdict(verdict)

    audit_log.log_verdict(verdict, command="scan")
    sys.exit(verdict.exit_code())


@main.command(name="scan-requirements")
@click.argument("requirements_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--offline", is_flag=True, help="Drop every network-dependent stage (LLM/advisory/metadata)")
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None,
              help="Path to allowlist file (default: auto-discover .wtfguardignore / WTFGUARD_ALLOWLIST / ~/.wtfguard/allowlist.txt)")
@click.option("--policy", "policy_path", type=click.Path(path_type=Path), default=None,
              help="YAML policy file with severity overrides")
@click.option("--sarif", "sarif_path", type=click.Path(path_type=Path), default=None,
              help="Write SARIF 2.1.0 report to this path")
@click.option("--html", "html_path", type=click.Path(path_type=Path), default=None,
              help="Write standalone HTML report to this path")
@click.option("--markdown", "markdown_path", type=click.Path(path_type=Path), default=None,
              help="Write Markdown report (for PR comments)")
@click.option("--cyclonedx", "cyclonedx_path", type=click.Path(path_type=Path), default=None,
              help="Write CycloneDX 1.5 SBOM JSON")
@click.option("--webhook", "webhook_url", default=None,
              help="POST a scan summary to this Slack/Discord/generic webhook URL")
@click.option("--min-severity", "min_severity_str",
              type=click.Choice(["clean", "low", "medium", "high", "critical"]),
              default="clean", help="Drop verdicts below this severity from output + exit-code")
@click.option("--json", "json_output", is_flag=True, help="Emit verdicts as a JSON array")
@click.option("--jobs", "-j", type=int, default=4, help="Concurrent scan workers (default 4)")
def scan_requirements(
    requirements_file: Path,
    no_llm: bool,
    no_cache: bool,
    offline: bool,
    allowlist_path: Path | None,
    policy_path: Path | None,
    sarif_path: Path | None,
    html_path: Path | None,
    markdown_path: Path | None,
    cyclonedx_path: Path | None,
    webhook_url: str | None,
    min_severity_str: str,
    json_output: bool,
    jobs: int,
) -> None:
    """Scan every pinned package in a requirements / lockfile.

    Supported formats: requirements.txt, requirements.in, poetry.lock,
    uv.lock, Pipfile.lock. Format is auto-detected by filename.
    """
    packages = lockfile.dedupe_packages(lockfile.parse_file(requirements_file))
    if not packages:
        console.print("[yellow]no packages parsed from file[/yellow]")
        sys.exit(0)

    rules = allowlist.load(allowlist_path)
    active_policy = policy.load(policy_path)
    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache, offline=offline)

    to_scan: list[tuple[str, str | None]] = []
    skipped: list[str] = []
    for name, version in packages:
        if rules.allows(name, version):
            if not json_output:
                console.print(f"[dim]allowlisted[/dim] {name}=={version or 'latest'}")
            skipped.append(f"{name}=={version or 'latest'}")
            continue
        to_scan.append((name, version))

    summary, worst = run_scan_batch(to_scan, options, jobs, json_mode=json_output,
                                    audit_command="scan-requirements", active_policy=active_policy)

    threshold = Severity.from_name(min_severity_str)
    if threshold > Severity.CLEAN:
        summary = [v for v in summary if v.severity >= threshold]
        worst = Severity(max((int(v.severity) for v in summary), default=int(Severity.CLEAN)))

    if json_output:
        emit_batch_json(summary, skipped, worst)
    else:
        console.print()
        render_requirements_summary(summary, worst)
        if skipped:
            console.print(f"[dim]allowlisted ({len(skipped)}):[/dim] {', '.join(skipped)}")
        if active_policy.source is not None:
            console.print(f"[dim]policy:[/] {active_policy.source} ({len(active_policy.overrides)} overrides)")
    if sarif_path is not None:
        write_sarif(summary, sarif_path)
    if html_path is not None:
        write_html(summary, skipped, html_path)
    if markdown_path is not None:
        write_markdown(summary, skipped, markdown_path)
    if cyclonedx_path is not None:
        write_cyclonedx(summary, cyclonedx_path)
    if webhook_url:
        ok = webhook.post(webhook_url, summary, worst)
        if not json_output:
            console.print("[green]webhook posted[/]" if ok else "[yellow]webhook delivery failed[/]")
    sys.exit(2 if worst >= Severity.CRITICAL else 1 if worst >= Severity.HIGH else 0)


@main.command(name="scan-installed")
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--offline", is_flag=True, help="Drop every network-dependent stage (LLM/advisory/metadata)")
@click.option("--include-stdlib", is_flag=True, help="Include pip / setuptools / wheel / packaging")
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None)
@click.option("--policy", "policy_path", type=click.Path(path_type=Path), default=None,
              help="YAML policy file with severity overrides")
@click.option("--max-packages", type=int, default=0, help="Cap scan at N packages (0 = no cap)")
@click.option("--sarif", "sarif_path", type=click.Path(path_type=Path), default=None,
              help="Write SARIF 2.1.0 report to this path")
@click.option("--html", "html_path", type=click.Path(path_type=Path), default=None,
              help="Write standalone HTML report to this path")
@click.option("--markdown", "markdown_path", type=click.Path(path_type=Path), default=None,
              help="Write Markdown report (for PR comments)")
@click.option("--cyclonedx", "cyclonedx_path", type=click.Path(path_type=Path), default=None,
              help="Write CycloneDX 1.5 SBOM JSON")
@click.option("--webhook", "webhook_url", default=None,
              help="POST a scan summary to this Slack/Discord/generic webhook URL")
@click.option("--min-severity", "min_severity_str",
              type=click.Choice(["clean", "low", "medium", "high", "critical"]),
              default="clean", help="Drop verdicts below this severity from output + exit-code")
@click.option("--json", "json_output", is_flag=True, help="Emit verdicts as a JSON array")
@click.option("--jobs", "-j", type=int, default=4, help="Concurrent scan workers (default 4)")
def scan_installed(
    no_llm: bool,
    no_cache: bool,
    offline: bool,
    include_stdlib: bool,
    allowlist_path: Path | None,
    policy_path: Path | None,
    max_packages: int,
    sarif_path: Path | None,
    html_path: Path | None,
    markdown_path: Path | None,
    cyclonedx_path: Path | None,
    webhook_url: str | None,
    min_severity_str: str,
    json_output: bool,
    jobs: int,
) -> None:
    """Scan every package installed in the current Python environment."""
    packages = installed.list_installed(include_stdlib=include_stdlib)
    if not packages:
        console.print("[yellow]no installed packages found[/yellow]")
        sys.exit(0)

    if max_packages > 0:
        packages = packages[:max_packages]

    rules = allowlist.load(allowlist_path)
    active_policy = policy.load(policy_path)
    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache, offline=offline)

    to_scan: list[tuple[str, str | None]] = []
    skipped: list[str] = []
    for pkg in packages:
        spec = f"{pkg.name}=={pkg.version}"
        if rules.allows(pkg.name, pkg.version):
            skipped.append(spec)
            continue
        to_scan.append((pkg.name, pkg.version))

    if not json_output:
        console.print(f"[bold]scanning {len(to_scan)} packages (jobs={jobs})[/bold]")
    summary, worst = run_scan_batch(to_scan, options, jobs, only_show_above=Severity.MEDIUM,
                                    json_mode=json_output, audit_command="scan-installed",
                                    active_policy=active_policy)

    threshold = Severity.from_name(min_severity_str)
    if threshold > Severity.CLEAN:
        summary = [v for v in summary if v.severity >= threshold]
        worst = Severity(max((int(v.severity) for v in summary), default=int(Severity.CLEAN)))

    if json_output:
        emit_batch_json(summary, skipped, worst)
    else:
        console.print()
        render_requirements_summary(summary, worst)
        if skipped:
            console.print(f"[dim]allowlisted ({len(skipped)}):[/dim] {', '.join(skipped)}")
    if sarif_path is not None:
        write_sarif(summary, sarif_path)
    if html_path is not None:
        write_html(summary, skipped, html_path)
    if markdown_path is not None:
        write_markdown(summary, skipped, markdown_path)
    if cyclonedx_path is not None:
        write_cyclonedx(summary, cyclonedx_path)
    if webhook_url:
        ok = webhook.post(webhook_url, summary, worst)
        if not json_output:
            console.print("[green]webhook posted[/]" if ok else "[yellow]webhook delivery failed[/]")
    sys.exit(2 if worst >= Severity.CRITICAL else 1 if worst >= Severity.HIGH else 0)


@main.command(name="achievements")
def achievements_cmd() -> None:
    """Show unlocked achievements and skip/read counts."""
    user_state = state.load_state()
    table = Table(title="wtfguard achievements")
    table.add_column("Achievement")
    table.add_column("Status")
    table.add_column("Progress")

    metric_value = {
        "skips_total": user_state.skips_total,
        "reads_total": user_state.reads_total,
        "scans_total": user_state.scans_total,
    }

    for ach in achievements.ALL_ACHIEVEMENTS:
        if ach.secret and ach.id not in user_state.achievements:
            row = ("???", "locked", f"{metric_value.get(ach.metric, 0)} / ???")
        else:
            unlocked = ach.id in user_state.achievements
            status = f"[{ach.color}]unlocked[/]" if unlocked else "locked"
            row = (ach.name, status, f"{metric_value.get(ach.metric, 0)} / {ach.threshold}")
        table.add_row(*row)

    console.print(table)
    console.print(f"\nscans:{user_state.scans_total}  skips:{user_state.skips_total}  reads:{user_state.reads_total}")


@main.command()
def tip() -> None:
    """Print one random security tip."""
    t = tips.random_tip()
    console.print(Panel(t.text, title=f"[bold]{t.level}[/bold]", border_style="cyan"))


@main.command(name="verify-baseline")
@click.argument("baseline_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--json", "json_output", is_flag=True, help="Emit diff as JSON")
@click.option("--jobs", "-j", type=int, default=4)
def verify_baseline_cmd(
    baseline_file: Path,
    no_llm: bool,
    no_cache: bool,
    json_output: bool,
    jobs: int,
) -> None:
    """Re-scan the same packages as a saved baseline and fail on drift.

    The baseline is the JSON output of an earlier `scan-requirements --json`
    or `scan-installed --json`. Useful as a CI gate: pin a clean state,
    then fail the PR build if any new finding appears.
    """
    try:
        baseline_payload = baseline_mod.load_baseline(baseline_file)
    except (OSError, ValueError) as exc:
        console.print(f"[red]error:[/] {type(exc).__name__}: {exc}")
        sys.exit(2)

    specs = baseline_mod.extract_specs(baseline_payload)
    if not specs:
        console.print("[yellow]baseline contains no scannable specs[/]")
        sys.exit(0)

    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)
    summary, worst = run_scan_batch(specs, options, jobs, json_mode=True)
    fresh_payload = baseline_mod.verdicts_to_payload(summary, worst.label())

    result = verdict_diff.diff(baseline_payload, fresh_payload)

    if json_output:
        payload = {
            "worst_before": result.worst_before.label(),
            "worst_after":  result.worst_after.label(),
            "added":        [vars(r) for r in result.added],
            "removed":      [vars(r) for r in result.removed],
            "severity_changed": [
                {"before": vars(a), "after": vars(b)}
                for a, b in result.severity_changed
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(verdict_diff.format_text(result))

    sys.exit(0 if result.is_empty() else 1)


@main.command(name="diff")
@click.argument("before", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("after", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="Emit diff as JSON")
def diff_cmd(before: Path, after: Path, json_output: bool) -> None:
    """Compare two JSON verdict outputs and report what changed.

    Both inputs may be single-scan JSON (from `scan --json`) or batch JSON
    (from `scan-requirements --json` / `scan-installed --json`). Exit code
    is 0 when there is no per-finding change, 1 otherwise.
    """
    try:
        before_payload = verdict_diff.load_json(before)
        after_payload = verdict_diff.load_json(after)
    except (OSError, ValueError) as exc:
        console.print(f"[red]error:[/] {type(exc).__name__}: {exc}")
        sys.exit(2)

    result = verdict_diff.diff(before_payload, after_payload)

    if json_output:
        payload = {
            "worst_before": result.worst_before.label(),
            "worst_after":  result.worst_after.label(),
            "added":        [vars(r) for r in result.added],
            "removed":      [vars(r) for r in result.removed],
            "severity_changed": [
                {"before": vars(a), "after": vars(b)}
                for a, b in result.severity_changed
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(verdict_diff.format_text(result))

    sys.exit(0 if result.is_empty() else 1)


@main.command(name="watch")
@click.argument("target", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--interval", type=float, default=1.0, help="Poll interval in seconds (default 1.0)")
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
def watch_cmd(target: Path, interval: float, no_llm: bool, no_cache: bool) -> None:
    """Watch a requirements / lockfile and re-scan on every change.

    Polls the file's mtime. Ideal for editor integration during dependency
    upgrades — save the file, see the new verdict in your terminal.
    """
    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)

    def re_scan(path: Path) -> None:
        console.print(f"[bold]change detected:[/] {path}")
        packages = lockfile.dedupe_packages(lockfile.parse_file(path))
        if not packages:
            console.print("[yellow]no packages parsed[/]")
            return
        items = [(n, v) for n, v in packages]
        summary, worst = run_scan_batch(items, options, jobs=4, only_show_above=Severity.MEDIUM)
        render_requirements_summary(summary, worst)

    re_scan(target)
    console.print(f"[dim]watching {target} (interval {interval}s) — Ctrl-C to stop[/]")
    try:
        watch.watch_file(target, on_change=re_scan, interval=interval)
    except KeyboardInterrupt:
        console.print("[yellow]watch stopped[/]")


@main.command()
@click.argument("package_name")
@click.option("--json", "json_output", is_flag=True, help="Emit metadata as JSON")
def show(package_name: str, json_output: bool) -> None:
    """Print a read-only metadata report for a PyPI package.

    Fetches PyPI metadata + OSV advisories without downloading the package.
    Use this to triage before deciding whether to install/scan.
    """
    meta = pypi_signals.fetch_metadata(package_name)
    if meta is None:
        console.print(f"[red]error:[/red] package {package_name} not found on PyPI")
        sys.exit(1)

    findings = pypi_signals.derive_findings(meta)
    advisories = advisory.lookup(package_name, meta.latest_version) if meta.latest_version else []

    if json_output:
        payload = {
            "name":              meta.name,
            "latest_version":    meta.latest_version,
            "summary":           meta.summary,
            "release_count":     meta.release_count,
            "first_release":     meta.first_release_at.isoformat() if meta.first_release_at else None,
            "last_release":      meta.last_release_at.isoformat() if meta.last_release_at else None,
            "project_urls":      meta.project_urls,
            "has_attestations":  meta.has_attestations,
            "attestation_count": meta.attestation_count,
            "signals":           [f.to_dict() for f in findings],
            "advisories":        [{"id": a.id, "severity": a.severity.label(), "summary": a.summary} for a in advisories],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    attestation_label = (
        f"[green]yes[/] ({meta.attestation_count} files signed)"
        if meta.has_attestations
        else "[yellow]no[/] (not using Trusted Publishers)"
    )
    body_lines: list[str] = [
        f"[bold]Latest version:[/]    {meta.latest_version}",
        f"[bold]Summary:[/]           {meta.summary or '(none)'}",
        f"[bold]Releases:[/]          {meta.release_count}",
        f"[bold]First release:[/]    {meta.first_release_at.date() if meta.first_release_at else 'unknown'}",
        f"[bold]Last release:[/]     {meta.last_release_at.date() if meta.last_release_at else 'unknown'}",
        f"[bold]Files in latest:[/]  {meta.latest_file_count}",
        f"[bold]PEP 740 signed:[/]   {attestation_label}",
    ]
    if meta.project_urls:
        urls = ", ".join(f"{k}={v}" for k, v in meta.project_urls.items())
        body_lines.append(f"[bold]URLs:[/] {urls}")
    if findings:
        body_lines.append("")
        body_lines.append("[bold]Metadata signals:[/]")
        for f in findings:
            color = SEVERITY_COLOR.get(f.severity, "white")
            body_lines.append(f"  [{color}]{f.severity.label():7}[/] {f.rule_id:24} {f.snippet}")
    if advisories:
        body_lines.append("")
        body_lines.append("[bold]Known advisories:[/]")
        for a in advisories:
            color = SEVERITY_COLOR.get(a.severity, "white")
            body_lines.append(f"  [{color}]{a.severity.label():7}[/] {a.id:24} {a.summary[:80]}")
    console.print(Panel("\n".join(body_lines), title=f"[bold]{meta.name}[/]", border_style="blue"))


@main.command()
@click.argument("rule_id")
@click.option("--rules", "extra_rules", type=click.Path(path_type=Path), multiple=True)
def explain(rule_id: str, extra_rules: tuple[Path, ...]) -> None:
    """Print everything we know about a single heuristic rule."""
    loaded = heuristics.load_rules(extra_paths=list(extra_rules) or load_env_rules())
    matches = [r for r in loaded if r.id.lower() == rule_id.lower()]
    if not matches:
        console.print(f"[red]no rule with id[/] {rule_id}")
        sys.exit(1)
    rule = matches[0]
    color = SEVERITY_COLOR.get(rule.severity, "white")
    body = (
        f"[bold]ID:[/]          {rule.id}\n"
        f"[bold]Severity:[/]    [{color}]{rule.severity.label()}[/]\n"
        f"[bold]File scope:[/] {rule.file_scope}\n"
        f"[bold]Pattern:[/]     {rule.regex.pattern}\n\n"
        f"{rule.description}"
    )
    console.print(Panel(body, title=f"[bold]{rule.id}[/]", border_style=color))


def load_env_rules() -> list[Path]:
    raw = os.getenv("WTFGUARD_RULES", "").strip()
    if not raw:
        return []
    return [Path(p) for p in raw.split(os.pathsep) if p.strip()]


@main.command(name="bench")
@click.option("--format", "fmt", type=click.Choice(["text", "markdown", "json"]), default="text")
@click.option("--golden-dir", "golden_dir", type=click.Path(path_type=Path), default=None,
              help="Override the bundled golden fixture directory")
@click.option("--network", is_flag=True,
              help="Run a shadow benchmark against the top-N real PyPI packages")
@click.option("--top", type=int, default=bench.NETWORK_BENCH_DEFAULT_TOP,
              help="Number of top packages to scan in --network mode")
def bench_cmd(fmt: str, golden_dir: Path | None, network: bool, top: int) -> None:
    """Run the heuristic engine against bundled golden fixtures and report FP/FN.

    With `--network`, instead runs against the top-N PyPI packages by
    download count — a real-world FP-rate measurement on assumed-legitimate
    packages.
    """
    if network:
        net_report = bench.run_network_benchmark(top=top)
        if fmt == "json":
            print(json.dumps({
                "scanned":         net_report.total,
                "failed":          net_report.failed_packages,
                "flagged_high":    net_report.flagged_high,
                "flagged_medium":  net_report.flagged_medium,
                "fp_rate_high":    net_report.fp_rate_high,
                "verdicts":        [v.to_dict() for v in net_report.verdicts],
            }, indent=2, ensure_ascii=False))
        else:
            print(bench.format_network_text(net_report))
        sys.exit(0 if net_report.flagged_high == 0 else 1)

    report = bench.run_benchmark(golden_dir)
    if fmt == "json":
        print(bench.format_json(report))
    elif fmt == "markdown":
        print(bench.format_markdown(report))
    else:
        print(bench.format_text(report))
    sys.exit(0 if report.false_positives == 0 and report.false_negatives == 0 else 1)


@main.command(name="scan-dir")
@click.argument("target", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--rules", "extra_rules", type=click.Path(path_type=Path), multiple=True,
              help="Extra rules YAML files")
@click.option("--name", "package_name", default=scan_dir.DEFAULT_PACKAGE_NAME,
              help="Name to label this verdict with")
@click.option("--version", "package_version", default="0.0.0")
@click.option("--json", "json_output", is_flag=True, help="Emit verdict as JSON")
def scan_dir_cmd(
    target: Path,
    extra_rules: tuple[Path, ...],
    package_name: str,
    package_version: str,
    json_output: bool,
) -> None:
    """Scan a local source tree before publishing — no PyPI fetch.

    Runs the heuristic engine (regex + AST + pyproject.toml) against every
    file under TARGET. No advisory lookup, no LLM, no PyPI metadata — fast,
    offline, deterministic. Use to dogfood your own package before release.
    """
    verdict = scan_dir.scan_local_directory(
        target,
        extra_rules=list(extra_rules) or None,
        package_name=package_name,
        package_version=package_version,
    )
    if json_output:
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    else:
        render_verdict(verdict)
    audit_log.log_verdict(verdict, command="scan-dir")
    sys.exit(verdict.exit_code())


@main.command(name="scan-tree")
@click.argument("package_spec")
@click.option("--max-depth", type=int, default=dependency_tree.DEFAULT_MAX_DEPTH,
              help="Stop walking transitive dependencies past this depth (default 3)")
@click.option("--max-nodes", type=int, default=dependency_tree.DEFAULT_MAX_NODES,
              help="Hard cap on total nodes resolved (default 200)")
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None)
@click.option("--json", "json_output", is_flag=True, help="Emit verdicts as JSON")
@click.option("--tree-only", is_flag=True, help="Just print the resolved tree, don't scan")
@click.option("--jobs", "-j", type=int, default=4)
def scan_tree_cmd(
    package_spec: str,
    max_depth: int,
    max_nodes: int,
    no_llm: bool,
    no_cache: bool,
    allowlist_path: Path | None,
    json_output: bool,
    tree_only: bool,
    jobs: int,
) -> None:
    """Resolve a package's transitive dependency tree and scan every node.

    Most supply-chain attacks ride in transitive dependencies — the one
    you didn't choose but pip pulled anyway. This walks `requires_dist`
    from PyPI metadata, capped at --max-depth and --max-nodes, then
    runs the full scan pipeline on each resolved package.
    """
    name, version = parse_package_spec(package_spec)
    tree = dependency_tree.resolve_tree(name, version, max_depth=max_depth, max_nodes=max_nodes)

    if tree_only:
        if json_output:
            print(json.dumps(dependency_tree.tree_to_dict(tree), indent=2, ensure_ascii=False))
        else:
            console.print(dependency_tree.format_tree(tree))
        return

    specs = dependency_tree.collect_nodes(tree)
    rules = allowlist.load(allowlist_path)
    to_scan: list[tuple[str, str | None]] = []
    skipped: list[str] = []
    for n, v in specs:
        if rules.allows(n, v):
            skipped.append(f"{n}=={v or 'latest'}")
            continue
        to_scan.append((n, v))

    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)
    if not json_output:
        console.print(f"[bold]resolved {len(specs)} nodes, scanning {len(to_scan)} (jobs={jobs})[/]")
    summary, worst = run_scan_batch(to_scan, options, jobs, only_show_above=Severity.MEDIUM,
                                    json_mode=json_output, audit_command="scan-tree")

    if json_output:
        payload = {
            "tree":     dependency_tree.tree_to_dict(tree),
            "verdicts": [v.to_dict() for v in summary],
            "worst":    worst.label(),
            "allowlisted": skipped,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        console.print()
        render_requirements_summary(summary, worst)
        if skipped:
            console.print(f"[dim]allowlisted ({len(skipped)}):[/] {', '.join(skipped)}")
    sys.exit(2 if worst >= Severity.CRITICAL else 1 if worst >= Severity.HIGH else 0)


@main.group(name="config")
def config_group() -> None:
    """Inspect the effective wtfguard configuration."""


@config_group.command(name="show")
@click.option("--json", "json_output", is_flag=True)
def config_show(json_output: bool) -> None:
    """Print the effective config plus where each value came from."""
    cfg = config.load()
    payload = {
        "source":    str(cfg.source) if cfg.source else None,
        "scan": {
            "jobs":     cfg.scan.jobs,
            "no_llm":   cfg.scan.no_llm,
            "no_cache": cfg.scan.no_cache,
            "rules":    cfg.scan.rules,
        },
        "llm": {
            "backend":           cfg.llm.backend,
            "model":             cfg.llm.model,
            "ollama_url":        cfg.llm.ollama_url,
            "anthropic_api_key": "***" if cfg.llm.anthropic_api_key else None,
        },
        "allowlist": {"path": cfg.allowlist.path},
        "env": {
            "WTFGUARD_LLM_BACKEND":  os.getenv("WTFGUARD_LLM_BACKEND"),
            "WTFGUARD_LLM_MODEL":    os.getenv("WTFGUARD_LLM_MODEL"),
            "WTFGUARD_OLLAMA_URL":   os.getenv("WTFGUARD_OLLAMA_URL"),
            "WTFGUARD_ALLOWLIST":    os.getenv("WTFGUARD_ALLOWLIST"),
            "WTFGUARD_RULES":        os.getenv("WTFGUARD_RULES"),
            "WTFGUARD_AUDIT_LOG":    os.getenv("WTFGUARD_AUDIT_LOG"),
            "WTFGUARD_AUDIT_DISABLED": os.getenv("WTFGUARD_AUDIT_DISABLED"),
            "ANTHROPIC_API_KEY":     "***" if os.getenv("ANTHROPIC_API_KEY") else None,
        },
    }

    if json_output:
        print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        return

    source = payload["source"]
    console.print(f"[bold]source:[/]   {source if source else '(none — using defaults)'}")

    def _render(label: str, key: str, width: int) -> None:
        section = payload.get(key)
        if not isinstance(section, dict):
            return
        console.print(f"\n[bold]\\[{label}][/]")
        for k, v in section.items():
            console.print(f"  {k:{width}} = {v}")

    _render("scan",      "scan",      9)
    _render("llm",       "llm",       18)
    _render("allowlist", "allowlist", 9)

    env_section = payload.get("env")
    if isinstance(env_section, dict):
        console.print("\n[bold]env vars:[/]")
        for k, v in env_section.items():
            marker = "[green]set[/]" if v is not None else "[dim]unset[/]"
            console.print(f"  {k:28} {marker}  {v if v is not None else ''}")


@main.command(name="self-test")
@click.option("--json", "json_output", is_flag=True)
def self_test_cmd(json_output: bool) -> None:
    """Sanity-check the wtfguard installation. Exits 1 on any failure."""
    report = self_test.run_all()
    if json_output:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(self_test.format_text(report))
    sys.exit(0 if report.fails == 0 else 1)


@main.command(name="sbom-merge")
@click.argument("inputs", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--output", "output_path", type=click.Path(path_type=Path), required=True,
              help="Where to write the merged CycloneDX 1.5 JSON")
def sbom_merge_cmd(inputs: tuple[Path, ...], output_path: Path) -> None:
    """Merge multiple CycloneDX 1.5 SBOMs into one.

    Components are deduplicated by `bom-ref` / `purl` / `name`,
    vulnerabilities by `id`. The resulting SBOM gets a fresh
    serialNumber and timestamp.
    """
    merged = sbom_merge.merge(list(inputs))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2, ensure_ascii=False)
    console.print(
        f"[green]merged[/] {len(inputs)} SBOM file(s) → {output_path} "
        f"({len(merged.get('components') or [])} components, "
        f"{len(merged.get('vulnerabilities') or [])} vulnerabilities)"
    )


@main.command(name="schema")
@click.argument("name", type=click.Choice(schemas.NAMES))
def schema_cmd(name: str) -> None:
    """Print the JSON Schema (or external reference) for a wtfguard output format.

    Useful for wiring tooling validators against `wtfguard scan --json`,
    `scan-requirements --json`, SARIF, or CycloneDX.
    """
    print(json.dumps(schemas.get_schema(name), indent=2, ensure_ascii=False, sort_keys=True))


@main.command(name="threats")
@click.option("--since", "since_str", default="30d",
              help="Only advisories for installed packages within this window (e.g. 7d, 24h, 2w)")
@click.option("--include-stdlib", is_flag=True, help="Include bootstrap packages (pip, setuptools, ...)")
@click.option("--min-severity", "min_severity",
              type=click.Choice(["clean", "low", "medium", "high", "critical"]),
              default="low", help="Hide threats below this severity")
@click.option("--json", "json_output", is_flag=True)
def threats_cmd(since_str: str, include_stdlib: bool, min_severity: str, json_output: bool) -> None:
    """List recent OSV advisories for every installed package.

    Combines `wtfguard scan-installed`'s discovery with the OSV.dev batch
    endpoint, producing a focused threat-intel report.
    """
    since = threats.parse_since(since_str)
    report = threats.scan_installed(since=since, include_stdlib=include_stdlib)

    threshold = Severity.from_name(min_severity)
    report.threats = [t for t in report.threats if t.severity >= threshold]

    if json_output:
        payload = {
            "scanned_count": report.scanned_count,
            "since":         since_str,
            "min_severity":  min_severity,
            "threats": [
                {
                    "package":     t.package,
                    "version":     t.version,
                    "advisory_id": t.advisory_id,
                    "severity":    t.severity.label(),
                    "summary":     t.summary,
                }
                for t in report.threats
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(threats.format_text(report))
    sys.exit(0 if not report.threats else 1)


POLICY_STARTER = """\
# wtfguard policy — severity overrides per rule and per package.
# Lookup chain: WTFGUARD_POLICY env, ./wtfguard-policy.yaml, no file.

overrides:
  # Downgrade NET_IN_SETUP for one internal package that legitimately
  # phones home for telemetry.
  # - rule: NET_IN_SETUP
  #   packages: [acme-internal]
  #   severity: low

  # Drop the LICENSE_INCOMPATIBLE finding entirely — your legal team
  # already cleared this category.
  # - rule: LICENSE_INCOMPATIBLE
  #   severity: ignore

  # Raise BRAND_NEW_PACKAGE to high — your shop refuses to install
  # anything published within the last 30 days, full stop.
  # - rule: BRAND_NEW_PACKAGE
  #   severity: high
"""


@main.command(name="incident")
@click.argument("package_name")
@click.option("--json", "json_output", is_flag=True)
def incident_cmd(package_name: str, json_output: bool) -> None:
    """Print a chronological release + advisory timeline for a package.

    Useful for incident post-mortems: when did a vulnerable version ship,
    when was the CVE disclosed, when did the fix arrive?
    """
    report = incident.build_report(package_name)
    if json_output:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return
    print(incident.format_text(report))


@main.command(name="prefetch")
@click.argument("requirements_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--dest", type=click.Path(path_type=Path), default=None,
              help="Target directory (default: ~/.wtfguard/prefetch)")
@click.option("--json", "json_output", is_flag=True)
def prefetch_cmd(requirements_file: Path, dest: Path | None, json_output: bool) -> None:
    """Pre-download sdists for every pinned package — populate cache for --offline scans."""
    packages = lockfile.dedupe_packages(lockfile.parse_file(requirements_file))
    report = prefetch.run(packages, dest=dest)
    if json_output:
        print(json.dumps({
            "total":     report.total,
            "succeeded": report.succeeded,
            "skipped":   report.skipped,
            "failed":    [{"spec": s, "reason": r} for s, r in report.failed],
        }, indent=2, ensure_ascii=False))
        return
    print(prefetch.format_text(report))
    sys.exit(0 if not report.failed else 1)


@main.group(name="policy-cli")
def policy_group() -> None:
    """Inspect and validate a YAML policy file."""


@policy_group.command(name="show")
@click.argument("policy_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=False)
@click.option("--json", "json_output", is_flag=True)
def policy_show(policy_file: Path | None, json_output: bool) -> None:
    """Display the loaded policy (auto-discovered if no path given)."""
    loaded = policy.load(policy_file)
    if json_output:
        payload = {
            "source":    str(loaded.source) if loaded.source else None,
            "overrides": [
                {
                    "rule":     o.rule,
                    "packages": sorted(o.packages),
                    "severity": o.severity.label() if o.severity else "ignore",
                }
                for o in loaded.overrides
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        return

    console.print(f"[bold]source:[/]    {loaded.source or '(no policy file found)'}")
    console.print(f"[bold]overrides:[/] {len(loaded.overrides)}")
    for o in loaded.overrides:
        sev = o.severity.label() if o.severity else "ignore"
        scope = "all packages" if not o.packages else ", ".join(sorted(o.packages))
        console.print(f"  {o.rule:24} → {sev:8}  ({scope})")


@policy_group.command(name="validate")
@click.argument("policy_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def policy_validate(policy_file: Path) -> None:
    """Validate a policy file: parses, lists overrides, surfaces unknown rule IDs."""
    loaded = policy.load(policy_file)
    known_rules = {r.id for r in heuristics.load_rules()}
    known_rules.update({
        "KNOWN_ADVISORY",
        "LOW_RELEASE_COUNT", "BRAND_NEW_PACKAGE", "STALE_PACKAGE",
        "MISSING_PROJECT_URL", "SINGLE_FILE_RELEASE", "LOW_DOWNLOAD_VOLUME",
        "TYPOSQUAT_CANDIDATE",
        "LICENSE_INCOMPATIBLE", "LICENSE_UNKNOWN",
    })

    if not loaded.overrides:
        console.print("[yellow]policy is empty — no overrides defined[/]")
        sys.exit(0)

    unknown: list[str] = []
    for override in loaded.overrides:
        if override.rule not in known_rules:
            unknown.append(override.rule)

    console.print(f"[bold]source:[/]    {loaded.source}")
    console.print(f"[bold]overrides:[/] {len(loaded.overrides)}")
    if unknown:
        console.print(f"\n[red]unknown rule ids:[/] {', '.join(sorted(set(unknown)))}")
        console.print("[dim]these overrides will never fire because the rules do not exist[/]")
        sys.exit(1)
    console.print("[green]policy is valid — all rule ids are known[/]")


@policy_group.command(name="init")
@click.option("--output", "output_path", type=click.Path(path_type=Path), default=None,
              help="Target file (default: ./wtfguard-policy.yaml)")
@click.option("--force", is_flag=True, help="Overwrite an existing file")
def policy_init(output_path: Path | None, force: bool) -> None:
    """Generate a starter `wtfguard-policy.yaml` with commented examples."""
    target = output_path or Path("wtfguard-policy.yaml")
    if target.exists() and not force:
        console.print(f"[yellow]skipped (exists):[/] {target} — use --force to overwrite")
        return
    target.write_text(POLICY_STARTER, encoding="utf-8")
    console.print(f"[green]wrote[/] {target}")


@main.group(name="audit-log")
def audit_log_group() -> None:
    """Inspect and rotate the append-only audit log."""


@audit_log_group.command(name="show")
@click.option("--limit", type=int, default=20, help="Show the last N entries (default 20)")
@click.option("--severity", type=click.Choice(["clean", "low", "medium", "high", "critical"]),
              default=None, help="Only entries at or above this severity")
@click.option("--command", "command_filter", default=None,
              help="Only entries from a given command")
@click.option("--json", "json_output", is_flag=True, help="Emit entries as JSON")
def audit_log_show(
    limit: int,
    severity: str | None,
    command_filter: str | None,
    json_output: bool,
) -> None:
    """Print recent entries from the audit log."""
    entries = audit_log.read_entries()
    if command_filter:
        entries = [e for e in entries if e.get("command") == command_filter]
    if severity:
        threshold = Severity.from_name(severity)
        entries = [
            e for e in entries
            if Severity.from_name(str(e.get("severity", "clean"))) >= threshold
        ]
    entries = entries[-limit:]

    if json_output:
        print(json.dumps(entries, indent=2, ensure_ascii=False))
        return

    if not entries:
        console.print("[yellow]no matching audit-log entries[/]")
        return

    table = Table(title=f"wtfguard audit log (last {len(entries)})")
    table.add_column("Timestamp")
    table.add_column("Command")
    table.add_column("Package")
    table.add_column("Severity")
    table.add_column("Findings", justify="right")
    for entry in entries:
        sev = str(entry.get("severity", "clean"))
        sev_color = SEVERITY_COLOR.get(Severity.from_name(sev), "white")
        table.add_row(
            str(entry.get("timestamp", "")),
            str(entry.get("command", "")),
            f"{entry.get('package', '')} {entry.get('version', '')}",
            f"[{sev_color}]{sev}[/]",
            str(entry.get("findings_count", 0)),
        )
    console.print(table)


@audit_log_group.command(name="prune")
@click.option("--days", type=int, required=True, help="Drop entries older than N days")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirm prompt")
def audit_log_prune(days: int, yes: bool) -> None:
    """Remove audit-log entries older than --days days."""
    if not yes and not click.confirm(f"Prune entries older than {days} days?", default=False):
        console.print("[yellow]aborted[/]")
        sys.exit(0)
    removed = audit_log.prune_older_than(days)
    console.print(f"removed {removed} entries")


@audit_log_group.command(name="stats")
@click.option("--json", "json_output", is_flag=True)
def audit_log_stats(json_output: bool) -> None:
    """Summarise the audit log: counts by severity and command."""
    entries = audit_log.read_entries()
    by_severity: dict[str, int] = {}
    by_command:  dict[str, int] = {}
    for entry in entries:
        sev = str(entry.get("severity", "unknown"))
        cmd = str(entry.get("command", "unknown"))
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_command[cmd] = by_command.get(cmd, 0) + 1

    if json_output:
        print(json.dumps({
            "total":       len(entries),
            "by_severity": by_severity,
            "by_command":  by_command,
        }, indent=2, ensure_ascii=False, sort_keys=True))
        return

    console.print(f"[bold]total entries:[/] {len(entries)}")
    if by_severity:
        console.print("\n[bold]by severity:[/]")
        for sev in ("critical", "high", "medium", "low", "clean"):
            if sev in by_severity:
                color = SEVERITY_COLOR.get(Severity.from_name(sev), "white")
                console.print(f"  [{color}]{sev:9}[/] {by_severity[sev]}")
    if by_command:
        console.print("\n[bold]by command:[/]")
        for cmd, n in sorted(by_command.items(), key=lambda x: -x[1]):
            console.print(f"  {cmd:20} {n}")


@main.command(name="refresh-popular")
@click.option("--top", type=int, default=500, help="Number of names to keep (default 500)")
@click.option("--output", "output_path", type=click.Path(path_type=Path), default=None,
              help="Write to a custom file (default: bundled data/popular_pypi.txt)")
@click.option("--dry-run", is_flag=True, help="Print the would-be list without writing")
def refresh_popular_cmd(top: int, output_path: Path | None, dry_run: bool) -> None:
    """Refresh the typosquat-detection popular-packages list from PyPI download stats."""
    names = bench.fetch_top_packages(top)
    if not names:
        console.print("[red]error:[/] could not fetch top-PyPI list from the network")
        sys.exit(1)

    if dry_run:
        print("\n".join(names))
        return

    count = typosquat.write_popular(names, output_path)
    target = output_path or typosquat.POPULAR_PATH
    console.print(f"[green]wrote[/] {count} names to {target}")


@main.group(name="cache")
def cache_group() -> None:
    """Inspect and clear the SQLite verdict / JSON advisory / JSON metadata caches."""


@cache_group.command(name="stats")
@click.option("--json", "json_output", is_flag=True)
def cache_stats(json_output: bool) -> None:
    """Show cache file sizes and entry counts."""
    verdict_path = Path.home() / ".wtfguard" / "cache.sqlite"
    advisory_path = Path.home() / ".wtfguard" / "advisory-cache.json"
    metadata_path = Path.home() / ".wtfguard" / "pypi-metadata-cache.json"

    stats: dict[str, object] = {
        "verdict_cache":  cache_file_stats(verdict_path),
        "advisory_cache": cache_file_stats(advisory_path),
        "metadata_cache": cache_file_stats(metadata_path),
    }

    if json_output:
        print(json.dumps(stats, indent=2, ensure_ascii=False, sort_keys=True))
        return

    console.print(f"[bold]verdict cache (SQLite):[/]   {format_cache_stats(stats['verdict_cache'])}")
    console.print(f"[bold]advisory cache (JSON):[/]    {format_cache_stats(stats['advisory_cache'])}")
    console.print(f"[bold]metadata cache (JSON):[/]    {format_cache_stats(stats['metadata_cache'])}")


@cache_group.command(name="clear")
@click.option("--verdict", "clear_verdict", is_flag=True, help="Clear the SQLite verdict cache")
@click.option("--advisory", "clear_advisory", is_flag=True, help="Clear the advisory JSON cache")
@click.option("--metadata", "clear_metadata", is_flag=True, help="Clear the PyPI metadata cache")
@click.option("--all", "clear_all", is_flag=True, help="Clear all three caches")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirm prompt")
def cache_clear(clear_verdict: bool, clear_advisory: bool, clear_metadata: bool,
                clear_all: bool, yes: bool) -> None:
    """Remove one or more cache files."""
    targets: list[Path] = []
    if clear_all or clear_verdict:
        targets.append(Path.home() / ".wtfguard" / "cache.sqlite")
    if clear_all or clear_advisory:
        targets.append(Path.home() / ".wtfguard" / "advisory-cache.json")
    if clear_all or clear_metadata:
        targets.append(Path.home() / ".wtfguard" / "pypi-metadata-cache.json")

    if not targets:
        console.print("[yellow]nothing to clear — pass at least one of --verdict/--advisory/--metadata/--all[/]")
        sys.exit(1)

    if not yes and not click.confirm(f"Delete {len(targets)} cache file(s)?", default=False):
        console.print("[yellow]aborted[/]")
        sys.exit(0)

    removed = 0
    for path in targets:
        if path.is_file():
            path.unlink()
            removed += 1
            console.print(f"removed {path}")
    console.print(f"{removed} cache file(s) removed")


def cache_file_stats(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"exists": False, "path": str(path)}
    size = path.stat().st_size
    return {"exists": True, "path": str(path), "size_bytes": size}


def format_cache_stats(stats: object) -> str:
    if not isinstance(stats, dict):
        return "(unknown)"
    if not stats.get("exists"):
        return f"[dim]absent[/] ({stats.get('path')})"
    size = int(stats.get("size_bytes", 0) or 0)
    return f"{format_size(size):>10}  {stats.get('path')}"


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    f = float(n) / 1024
    if f < 1024:
        return f"{f:.1f} KB"
    f /= 1024
    if f < 1024:
        return f"{f:.1f} MB"
    return f"{f / 1024:.1f} GB"


@main.command(name="completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion_cmd(shell: str) -> None:
    """Print a shell-completion script for SHELL (bash | zsh | fish).

    Pipe the output into a file in your shell's completion directory:

        wtfguard completion bash > ~/.local/share/bash-completion/completions/wtfguard
        wtfguard completion zsh  > ~/.zsh/completions/_wtfguard
        wtfguard completion fish > ~/.config/fish/completions/wtfguard.fish
    """
    instruction = f"_WTFGUARD_COMPLETE={shell}_source wtfguard"
    import subprocess as _subprocess
    env = dict(os.environ)
    env["_WTFGUARD_COMPLETE"] = f"{shell}_source"
    result = _subprocess.run(["wtfguard"], env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout:
        console.print(f"[red]could not generate completion via Click; run manually:[/] {instruction}")
        sys.exit(1)
    print(result.stdout)


@main.command(name="pre-commit-config")
@click.option("--include-requirements", is_flag=True,
              help="Include a scan-requirements hook as well")
def pre_commit_config_cmd(include_requirements: bool) -> None:
    """Print a `.pre-commit-config.yaml` snippet you can paste into your repo."""
    base = (
        "repos:\n"
        "  - repo: https://github.com/wachawo/wtfguard\n"
        "    rev: main           # pin to a tag or SHA in production\n"
        "    hooks:\n"
        "      - id: wtfguard-scan-dir\n"
        "        name: wtfguard pre-publish self-scan\n"
        "        entry: wtfguard scan-dir src\n"
        "        language: system\n"
        "        pass_filenames: false\n"
    )
    if include_requirements:
        base += (
            "      - id: wtfguard-scan-requirements\n"
            "        name: wtfguard requirements scan\n"
            "        entry: wtfguard scan-requirements requirements.txt --no-llm\n"
            "        language: system\n"
            "        pass_filenames: false\n"
            "        files: ^requirements\\.txt$\n"
        )
    print(base.rstrip())


@main.command(name="rules")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--rules", "extra_rules", type=click.Path(path_type=Path), multiple=True,
              help="Extra rules YAML files (can be passed multiple times)")
def rules_cmd(fmt: str, extra_rules: tuple[Path, ...]) -> None:
    """List every heuristic rule loaded from patterns.yaml."""
    loaded = heuristics.load_rules(extra_paths=list(extra_rules) or load_env_rules())
    if fmt == "json":
        payload = [
            {
                "id":          r.id,
                "severity":    r.severity.label(),
                "file_scope":  r.file_scope,
                "description": r.description,
                "regex":       r.regex.pattern,
            }
            for r in loaded
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    table = Table(title=f"wtfguard heuristic rules ({len(loaded)})")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Scope")
    table.add_column("Description")
    for r in sorted(loaded, key=lambda r: (-int(r.severity), r.id)):
        sev_color = SEVERITY_COLOR.get(r.severity, "white")
        table.add_row(
            r.id,
            f"[{sev_color}]{r.severity.label()}[/]",
            r.file_scope,
            r.description,
        )
    console.print(table)


@main.command(name="init")
@click.option("--force", is_flag=True, help="Overwrite existing files")
@click.option("--dir", "target_dir", type=click.Path(path_type=Path), default=None,
              help="Initialise in this directory (default: cwd)")
def init_cmd(force: bool, target_dir: Path | None) -> None:
    """Create starter wtfguard.toml and .wtfguardignore in the current directory."""
    base = target_dir or Path.cwd()
    written: list[str] = []
    skipped: list[str] = []

    for filename, body in STARTER_FILES.items():
        target = base / filename
        if target.exists() and not force:
            skipped.append(filename)
            continue
        target.write_text(body, encoding="utf-8")
        written.append(filename)

    for name in written:
        console.print(f"[green]wrote[/] {base / name}")
    for name in skipped:
        console.print(f"[yellow]skipped (exists)[/] {base / name} — use --force to overwrite")


STARTER_FILES = {
    "wtfguard.toml": (
        "# wtfguard project config — committed to the repo.\n"
        "# Env vars and CLI flags always win over these defaults.\n"
        "\n"
        "[scan]\n"
        "jobs = 4\n"
        "# no_llm = true       # uncomment to skip the LLM stage by default\n"
        "\n"
        "[llm]\n"
        "# backend = \"ollama\"   # or \"claude\"\n"
        "# model = \"qwen2.5-coder:7b\"\n"
        "# ollama_url = \"http://localhost:11434\"\n"
        "\n"
        "[allowlist]\n"
        "path = \".wtfguardignore\"\n"
    ),
    ".wtfguardignore": (
        "# wtfguard allowlist — one entry per line.\n"
        "# Bare names (any version), pinned (name==version), or globs (acme-*).\n"
        "\n"
        "# requests\n"
        "# numpy==1.26.0\n"
        "# internal-*\n"
    ),
}


@main.command(name="pip", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None)
@click.option("--fail-on", type=click.Choice(["low", "medium", "high", "critical"]), default="critical",
              help="Minimum severity that aborts install")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirm prompt on high (still blocks critical)")
@click.pass_context
def pip_cmd(
    ctx: click.Context,
    no_llm: bool,
    no_cache: bool,
    allowlist_path: Path | None,
    fail_on: str,
    yes: bool,
) -> None:
    """Pre-install scanner around the real pip. Example: `wtfguard pip install requests`."""
    pip_argv: list[str] = list(ctx.args)
    parsed = pip_wrapper.parse_pip_args(pip_argv)

    env_report = system_env.inspect()
    warning = env_report.warning_text()
    if warning:
        console.print(f"[yellow]warning:[/] {warning}")

    if pip_wrapper.should_skip_scan(parsed):
        sys.exit(pip_wrapper.delegate_to_pip(pip_argv))

    if not parsed.specs:
        console.print("[yellow]no package specs to scan — delegating to pip[/]")
        sys.exit(pip_wrapper.delegate_to_pip(pip_argv))

    threshold = Severity.from_name(fail_on)
    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)
    console.print(f"[bold]wtfguard pre-install scan[/] of {len(parsed.specs)} package(s)")
    verdicts, worst, skipped_pkgs = pip_wrapper.scan_specs(parsed.specs, options, allowlist_path)

    for verdict in verdicts:
        if verdict.severity >= Severity.MEDIUM:
            render_verdict(verdict, compact=True)

    if worst >= threshold:
        console.print(f"[red bold]BLOCKED:[/] worst severity {worst.label()} >= threshold {fail_on}")
        sys.exit(2)

    if (worst >= Severity.HIGH and not yes
            and not click.confirm(f"Severity {worst.label()} found — proceed with install?", default=False)):
        console.print("[yellow]aborted by user[/]")
        sys.exit(1)

    if skipped_pkgs:
        console.print(f"[dim]allowlisted ({len(skipped_pkgs)}):[/] {', '.join(skipped_pkgs)}")

    console.print("[green]scan clean — delegating to pip[/]")
    sys.exit(pip_wrapper.delegate_to_pip(pip_argv))


@main.command()
def doctor() -> None:
    """Show config: cache path, state path, LLM availability."""
    backend = llm.active_backend()
    requested = llm.configured_backend()
    env_report = system_env.inspect()

    console.print(f"version:        [bold]{__version__}[/bold]")
    console.print("cache:          ~/.wtfguard/cache.sqlite")
    console.print("state:          ~/.wtfguard/state.json")
    console.print(f"python:         {env_report.python_executable}")
    console.print(f"virtualenv:     {'yes' if env_report.is_virtualenv else 'no'}")
    if env_report.is_externally_managed:
        marker_color = "green" if env_report.is_virtualenv else "red"
        console.print(f"PEP 668:        [{marker_color}]externally-managed (marker: {env_report.marker_path})[/]")
    else:
        console.print("PEP 668:        not externally-managed")
    console.print(f"backend (env):  {requested or '(autodetect)'}")
    color = "green" if backend else "yellow"
    console.print(f"backend (live): [{color}]{backend or 'none'}[/]")
    if backend == llm.BACKEND_CLAUDE:
        console.print(f"model:          {llm.default_model_for(backend)}")
    elif backend == llm.BACKEND_OLLAMA:
        console.print(f"model:          {llm.default_model_for(backend)}")
        console.print(f"ollama-url:     {llm.ollama_url()}")
    else:
        console.print("model:          [dim](no backend reachable)[/]")

    warning = env_report.warning_text()
    if warning:
        console.print(f"\n[yellow]warning:[/] {warning}")


@main.command()
@click.argument("package_spec")
def verify(package_spec: str) -> None:
    """Re-scan a package and compare the new verdict to the cached one.

    Useful for sanity-checking stale cache entries before relying on them.
    Exits 0 if verdicts agree, 1 if they disagree, 2 on error.
    """
    name, version = parse_package_spec(package_spec)
    options = analyzer.AnalysisOptions(use_llm=False, use_cache=False)

    try:
        fresh = analyzer.analyze_package(name, version, None, options)
    except LookupError as exc:
        console.print(f"[red]error:[/red] {exc}")
        sys.exit(2)

    if fresh.diff_hash is None:
        render_verdict(fresh)
        console.print("[yellow]no diff_hash → nothing to verify against (snapshot mode)[/]")
        sys.exit(0)

    with VerdictCache() as cache:
        cached = cache.get(fresh.diff_hash)

    if cached is None:
        render_verdict(fresh)
        console.print("[yellow]no cache entry → nothing to verify against[/]")
        sys.exit(0)

    matches = cached.severity == fresh.severity and len(cached.findings) == len(fresh.findings)
    render_verdict(fresh)
    if matches:
        console.print(f"[green]verdict matches cache[/] (severity={fresh.severity.label()}, "
                      f"findings={len(fresh.findings)})")
        sys.exit(0)
    console.print(
        f"[red]VERDICT MISMATCH[/]\n"
        f"  cached: severity={cached.severity.label()}, findings={len(cached.findings)}\n"
        f"  fresh:  severity={fresh.severity.label()}, findings={len(fresh.findings)}"
    )
    sys.exit(1)


def run_scan_batch(
    items: list[tuple[str, str | None]],
    options: analyzer.AnalysisOptions,
    jobs: int,
    only_show_above: Severity = Severity.CLEAN,
    json_mode: bool = False,
    audit_command: str | None = None,
    active_policy: policy.Policy | None = None,
) -> tuple[list[Verdict], Severity]:
    """Concurrently analyze each (name, version) tuple. Returns verdicts + worst severity."""
    if not items:
        return [], Severity.CLEAN

    def one(item: tuple[str, str | None]) -> Verdict | None:
        name, version = item
        try:
            return analyzer.analyze_package(name, version, None, options)
        except LookupError as exc:
            if not json_mode:
                console.print(f"  [red]skip:[/red] {name}=={version or 'latest'} — {exc}")
            return None

    def on_error(item: tuple[str, str | None], exc: BaseException) -> Verdict | None:
        name, version = item
        if not json_mode:
            console.print(f"  [red]error:[/red] {name}=={version or 'latest'} — {type(exc).__name__}: {exc}")
        return None

    raw = concurrency.map_parallel(one, items, jobs=max(1, jobs), on_error=on_error)
    verdicts: list[Verdict] = [v for v in raw if v is not None]

    if active_policy is not None and not active_policy.is_empty():
        verdicts = [policy.apply(v, active_policy) for v in verdicts]

    worst = Severity.CLEAN
    for verdict in verdicts:
        worst = Severity(max(int(worst), int(verdict.severity)))
        if not json_mode and verdict.severity >= only_show_above:
            render_verdict(verdict, compact=True)

    if audit_command:
        audit_log.log_batch(verdicts, command=audit_command)
    return verdicts, worst


def emit_batch_json(verdicts: list[Verdict], skipped: list[str], worst: Severity) -> None:
    payload = {
        "verdicts":    [v.to_dict() for v in verdicts],
        "allowlisted": skipped,
        "worst":       worst.label(),
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def write_sarif(verdicts: list[Verdict], path: Path) -> None:
    report = sarif.build_report(verdicts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    console.print(f"[green]SARIF report written:[/] {path}")


def write_html(verdicts: list[Verdict], allowlisted: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_report.render(verdicts, allowlisted), encoding="utf-8")
    console.print(f"[green]HTML report written:[/] {path}")


def write_markdown(verdicts: list[Verdict], allowlisted: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown_report.render(verdicts, allowlisted), encoding="utf-8")
    console.print(f"[green]Markdown report written:[/] {path}")


def write_cyclonedx(verdicts: list[Verdict], path: Path) -> None:
    bom = cyclonedx.build_bom(verdicts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2, ensure_ascii=False)
    console.print(f"[green]CycloneDX SBOM written:[/] {path}")


def parse_package_spec(spec: str) -> tuple[str, str | None]:
    if "==" in spec:
        name, version = spec.split("==", 1)
        return name.strip(), version.strip()
    return spec.strip(), None


def parse_requirements_file(path: Path) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            version = version.split(";")[0].split(" ")[0].strip()
            out.append((name.strip(), version))
        else:
            out.append((line.split(";")[0].strip(), None))
    return out


def pick_talkative(state_value: bool, flag: bool | None, silent: bool | None) -> bool:
    if silent:
        return False
    if flag is not None:
        return flag
    if os.getenv("WTFGUARD_TALKATIVE", "").lower() in TRUE_VALUES:
        return True
    return state_value


def print_tip(t: tips.Tip) -> None:
    color = {"incident": "red", "best-practice": "cyan", "joke": "magenta"}.get(t.level, "white")
    console.print(f"  [dim]tip[/] [{color}]{t.level}[/]  {t.text}")


def render_verdict(verdict: Verdict, compact: bool = False) -> None:
    color = SEVERITY_COLOR.get(verdict.severity, "white")
    header = f"[bold {color}]{verdict.severity.label().upper()}[/]"
    title = f"{header}  {verdict.package} {verdict.version}  (confidence {verdict.confidence:.2f})"

    body_lines: list[str] = []
    if verdict.findings:
        for f in verdict.findings[: 50 if not compact else 5]:
            body_lines.append(
                f"  [{SEVERITY_COLOR.get(f.severity, 'white')}]{f.severity.label():8}[/] "
                f"[bold]{f.rule_id:20}[/] {f.file}:{f.line}  {f.snippet}"
            )
        if compact and len(verdict.findings) > 5:
            body_lines.append(f"  ... {len(verdict.findings) - 5} more findings")
    else:
        body_lines.append("  [green]no heuristic findings[/]")

    if verdict.llm_explanation:
        body_lines.append("")
        body_lines.append(f"  [dim]LLM ({verdict.model}):[/] {verdict.llm_explanation}")

    console.print(Panel("\n".join(body_lines), title=title, border_style=color))


def render_requirements_summary(verdicts: list[Verdict], worst: Severity) -> None:
    table = Table(title="scan summary")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Severity")
    table.add_column("Findings")
    for v in verdicts:
        table.add_row(
            v.package,
            v.version,
            f"[{SEVERITY_COLOR.get(v.severity, 'white')}]{v.severity.label()}[/]",
            str(len(v.findings)),
        )
    console.print(table)
    console.print(f"overall: [{SEVERITY_COLOR.get(worst, 'white')}]{worst.label()}[/]")


def apply_achievements(user_state: state.State) -> None:
    unlocked = achievements.newly_unlocked(user_state)
    if not unlocked:
        return
    achievements.mark_unlocked(user_state, unlocked)
    for ach in unlocked:
        if ach.secret:
            print_secret_reveal(ach, user_state)
        else:
            console.print(f"\n[bold {ach.color}]ACHIEVEMENT UNLOCKED:[/] {ach.name} ({ach.metric}={ach.threshold})")


def print_secret_reveal(ach: achievements.Achievement, user_state: state.State) -> None:
    console.print()
    console.print(Panel(
        f"You have skipped [bold red]{user_state.skips_total}[/] security tips.\n\n"
        "If this were a real malicious actor, you would already be f*cked.\n"
        "But it's not, so: well done finishing the easter egg. Take tip #1001 — and read it.\n\n"
        "[bold]TIP #1001:[/] Pin dependencies by hash, not by version. "
        "`pip install foo==1.2.3 --hash=sha256:...`. Hash mismatch fails install before code runs.\n\n"
        "Talkative mode has been switched off. Re-enable with `wtfguard scan ... --talkative`.",
        title=f"[bold magenta]Achievement: {ach.name}[/]",
        border_style="magenta",
    ))
    user_state.talkative = False
    time.sleep(2)


if __name__ == "__main__":
    main()
