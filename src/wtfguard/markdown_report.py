#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Markdown audit report — designed to be pasted into a GitHub PR comment.

Same shape as the HTML report but rendered as plain CommonMark so it
displays correctly on github.com, gitlab.com, and most static-site CIs.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from wtfguard import __version__
from wtfguard.models import Finding, Severity, Verdict

SEVERITY_EMOJI = {
    Severity.CLEAN:    ":white_check_mark:",
    Severity.LOW:      ":information_source:",
    Severity.MEDIUM:   ":warning:",
    Severity.HIGH:     ":x:",
    Severity.CRITICAL: ":rotating_light:",
}


def render(verdicts: Iterable[Verdict], allowlisted: Iterable[str] = ()) -> str:
    verdict_list = list(verdicts)
    allow_list = list(allowlisted)
    worst = worst_severity(verdict_list)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    with_findings = sum(1 for v in verdict_list if v.findings)

    out: list[str] = [
        f"## wtfguard supply-chain audit {SEVERITY_EMOJI.get(worst, '')}",
        "",
        f"Worst severity: **{worst.label().upper()}** &middot; "
        f"scanned **{len(verdict_list)}** package(s) &middot; "
        f"**{with_findings}** with findings &middot; "
        f"**{len(allow_list)}** allowlisted",
        "",
        f"<sub>wtfguard {__version__} &middot; {now}</sub>",
        "",
    ]

    if verdict_list:
        out.append("### Summary")
        out.append("")
        out.append("| Package | Version | Severity | Findings |")
        out.append("|---|---|---|---:|")
        for v in verdict_list:
            out.append(
                f"| `{v.package}` | `{v.version}` | "
                f"{SEVERITY_EMOJI.get(v.severity, '')} **{v.severity.label()}** | "
                f"{len(v.findings)} |"
            )
        out.append("")

    detail_blocks = [render_verdict(v) for v in verdict_list if v.findings or v.llm_explanation]
    if detail_blocks:
        out.append("### Findings")
        out.append("")
        out.extend(detail_blocks)

    if allow_list:
        out.append("### Allowlisted")
        out.append("")
        for spec in allow_list:
            out.append(f"- `{spec}`")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def render_verdict(verdict: Verdict) -> str:
    emoji = SEVERITY_EMOJI.get(verdict.severity, "")
    lines = [
        f"<details><summary>{emoji} <code>{verdict.package} {verdict.version}</code> "
        f"&mdash; <strong>{verdict.severity.label()}</strong> "
        f"(confidence {verdict.confidence:.2f})</summary>",
        "",
    ]
    for f in verdict.findings:
        lines.append(render_finding(f))
    if verdict.llm_explanation:
        lines.append("")
        lines.append(f"> LLM ({verdict.model or 'unknown'}): {verdict.llm_explanation}")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return "\n".join(lines)


def render_finding(finding: Finding) -> str:
    emoji = SEVERITY_EMOJI.get(finding.severity, "")
    snippet = finding.snippet.replace("`", "\\`")
    return (
        f"- {emoji} **{finding.rule_id}** &nbsp; "
        f"`{finding.file}:{finding.line}` &nbsp; {finding.description}\n"
        f"  ```\n  {snippet}\n  ```"
    )


def worst_severity(verdicts: list[Verdict]) -> Severity:
    if not verdicts:
        return Severity.CLEAN
    return Severity(max(int(v.severity) for v in verdicts))
