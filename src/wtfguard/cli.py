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
    allowlist,
    analyzer,
    bench,
    concurrency,
    config,
    heuristics,
    html_report,
    installed,
    llm,
    lockfile,
    pip_wrapper,
    sarif,
    state,
    tips,
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

    sys.exit(verdict.exit_code())


@main.command(name="scan-requirements")
@click.argument("requirements_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None,
              help="Path to allowlist file (default: auto-discover .wtfguardignore / WTFGUARD_ALLOWLIST / ~/.wtfguard/allowlist.txt)")
@click.option("--sarif", "sarif_path", type=click.Path(path_type=Path), default=None,
              help="Write SARIF 2.1.0 report to this path")
@click.option("--html", "html_path", type=click.Path(path_type=Path), default=None,
              help="Write standalone HTML report to this path")
@click.option("--json", "json_output", is_flag=True, help="Emit verdicts as a JSON array")
@click.option("--jobs", "-j", type=int, default=4, help="Concurrent scan workers (default 4)")
def scan_requirements(
    requirements_file: Path,
    no_llm: bool,
    no_cache: bool,
    allowlist_path: Path | None,
    sarif_path: Path | None,
    html_path: Path | None,
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
    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)

    to_scan: list[tuple[str, str | None]] = []
    skipped: list[str] = []
    for name, version in packages:
        if rules.allows(name, version):
            if not json_output:
                console.print(f"[dim]allowlisted[/dim] {name}=={version or 'latest'}")
            skipped.append(f"{name}=={version or 'latest'}")
            continue
        to_scan.append((name, version))

    summary, worst = run_scan_batch(to_scan, options, jobs, json_mode=json_output)

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
    sys.exit(2 if worst >= Severity.CRITICAL else 1 if worst >= Severity.HIGH else 0)


@main.command(name="scan-installed")
@click.option("--no-llm", is_flag=True)
@click.option("--no-cache", is_flag=True)
@click.option("--include-stdlib", is_flag=True, help="Include pip / setuptools / wheel / packaging")
@click.option("--allowlist", "allowlist_path", type=click.Path(path_type=Path), default=None)
@click.option("--max-packages", type=int, default=0, help="Cap scan at N packages (0 = no cap)")
@click.option("--sarif", "sarif_path", type=click.Path(path_type=Path), default=None,
              help="Write SARIF 2.1.0 report to this path")
@click.option("--html", "html_path", type=click.Path(path_type=Path), default=None,
              help="Write standalone HTML report to this path")
@click.option("--json", "json_output", is_flag=True, help="Emit verdicts as a JSON array")
@click.option("--jobs", "-j", type=int, default=4, help="Concurrent scan workers (default 4)")
def scan_installed(
    no_llm: bool,
    no_cache: bool,
    include_stdlib: bool,
    allowlist_path: Path | None,
    max_packages: int,
    sarif_path: Path | None,
    html_path: Path | None,
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
    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)

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
    summary, worst = run_scan_batch(to_scan, options, jobs, only_show_above=Severity.MEDIUM, json_mode=json_output)

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


@main.command(name="bench")
@click.option("--format", "fmt", type=click.Choice(["text", "markdown", "json"]), default="text")
@click.option("--golden-dir", "golden_dir", type=click.Path(path_type=Path), default=None,
              help="Override the bundled golden fixture directory")
def bench_cmd(fmt: str, golden_dir: Path | None) -> None:
    """Run the heuristic engine against bundled golden fixtures and report FP/FN."""
    report = bench.run_benchmark(golden_dir)
    if fmt == "json":
        print(bench.format_json(report))
    elif fmt == "markdown":
        print(bench.format_markdown(report))
    else:
        print(bench.format_text(report))
    sys.exit(0 if report.false_positives == 0 and report.false_negatives == 0 else 1)


@main.command(name="rules")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
def rules_cmd(fmt: str) -> None:
    """List every heuristic rule loaded from patterns.yaml."""
    loaded = heuristics.load_rules()
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
    console.print(f"version:        [bold]{__version__}[/bold]")
    console.print("cache:          ~/.wtfguard/cache.sqlite")
    console.print("state:          ~/.wtfguard/state.json")
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

    worst = Severity.CLEAN
    for verdict in verdicts:
        worst = Severity(max(int(worst), int(verdict.severity)))
        if not json_mode and verdict.severity >= only_show_above:
            render_verdict(verdict, compact=True)
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
