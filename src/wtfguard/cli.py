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

from wtfguard import __version__, achievements, analyzer, llm, state, tips
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
def scan(
    package_spec: str,
    base_version: str | None,
    no_llm: bool,
    no_cache: bool,
    talkative_flag: bool | None,
    silent_flag: bool | None,
    json_output: bool,
) -> None:
    """Scan a PyPI package. PACKAGE_SPEC can be `requests` or `requests==2.32.0`."""
    name, version = parse_package_spec(package_spec)
    user_state = state.load_state()
    talkative = pick_talkative(user_state.talkative, talkative_flag, silent_flag)

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
def scan_requirements(requirements_file: Path, no_llm: bool, no_cache: bool) -> None:
    """Scan every pinned package in a requirements.txt-style file."""
    packages = parse_requirements_file(requirements_file)
    if not packages:
        console.print("[yellow]no packages parsed from file[/yellow]")
        sys.exit(0)

    options = analyzer.AnalysisOptions(use_llm=not no_llm, use_cache=not no_cache)
    summary: list[Verdict] = []
    worst = Severity.CLEAN

    for name, version in packages:
        console.print(f"[bold]scanning[/bold] {name}=={version or 'latest'}")
        try:
            verdict = analyzer.analyze_package(name, version, None, options)
        except LookupError as exc:
            console.print(f"  [red]skip:[/red] {exc}")
            continue
        summary.append(verdict)
        worst = Severity(max(int(worst), int(verdict.severity)))
        render_verdict(verdict, compact=True)

    console.print()
    render_requirements_summary(summary, worst)
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


@main.command()
def doctor() -> None:
    """Show config: cache path, state path, LLM availability."""
    console.print(f"version:        [bold]{__version__}[/bold]")
    console.print("cache:          ~/.wtfguard/cache.sqlite")
    console.print("state:          ~/.wtfguard/state.json")
    console.print(f"LLM available:  [{'green' if llm.is_available() else 'yellow'}]{llm.is_available()}[/]")
    console.print(f"LLM model:      {llm.DEFAULT_MODEL}")


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
