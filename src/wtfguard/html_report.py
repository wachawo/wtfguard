#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Standalone single-file HTML audit report generator.

The output is dependency-free HTML5 — opens in any browser, embeddable
in static-site CI artifacts, easy to email to a CISO.
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from datetime import UTC, datetime

from wtfguard import __version__
from wtfguard.models import Finding, Severity, Verdict

SEVERITY_COLOR = {
    Severity.CLEAN:    "#0e7a3b",
    Severity.LOW:      "#406bff",
    Severity.MEDIUM:   "#b88500",
    Severity.HIGH:     "#cc4400",
    Severity.CRITICAL: "#bb1a1a",
}

CSS = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0;
  background: #f6f7f9;
  color: #1a1a1a;
}
header {
  background: #1a1d22;
  color: #f3f5f7;
  padding: 18px 28px;
  border-bottom: 4px solid #406bff;
}
header h1 { margin: 0 0 4px; font-size: 20px; font-weight: 600; }
header .meta { font-size: 12px; opacity: 0.75; }
.summary {
  display: flex;
  gap: 16px;
  padding: 16px 28px;
  background: #ffffff;
  border-bottom: 1px solid #e1e4e8;
}
.summary .pill {
  padding: 8px 16px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 13px;
  color: #fff;
}
.summary .count {
  padding: 8px 14px;
  font-size: 13px;
  border: 1px solid #e1e4e8;
  border-radius: 6px;
  color: #555;
}
main { padding: 16px 28px 48px; }
table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}
th, td {
  text-align: left;
  padding: 10px 14px;
  font-size: 13px;
  border-bottom: 1px solid #f0f1f3;
}
th { background: #fafbfc; font-weight: 600; color: #444; }
tr:last-child td { border-bottom: none; }
tr.clickable { cursor: pointer; }
tr.clickable:hover { background: #fafbfc; }
.findings-row td { padding: 0; background: #fbfbfd; }
.findings-row.hidden { display: none; }
.findings-inner { padding: 12px 28px; }
.finding {
  background: #fff;
  border: 1px solid #ecedf1;
  border-radius: 6px;
  padding: 8px 12px;
  margin-bottom: 6px;
  font-family: "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px;
}
.finding .row { display: flex; gap: 10px; align-items: center; }
.finding .rule { font-weight: 600; min-width: 180px; }
.finding .file { color: #555; }
.finding .desc { color: #444; font-family: inherit; margin-top: 4px; font-size: 12px; }
.tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  color: #fff;
}
footer { padding: 16px 28px; text-align: center; font-size: 11px; color: #888; }
"""

JS = """
document.querySelectorAll('tr.clickable').forEach(row => {
  row.addEventListener('click', () => {
    const target = document.getElementById(row.dataset.target);
    if (target) target.classList.toggle('hidden');
  });
});
"""


def render(verdicts: Iterable[Verdict], allowlisted: Iterable[str] = ()) -> str:
    """Render a complete HTML document for the given verdicts."""
    verdict_list = list(verdicts)
    allow_list = list(allowlisted)
    worst = worst_severity(verdict_list)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    body_rows: list[str] = []
    for idx, verdict in enumerate(verdict_list):
        body_rows.append(render_row(verdict, idx))

    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>wtfguard report</title><style>{CSS}</style></head>"
        "<body>"
        + render_header(now)
        + render_summary(verdict_list, worst, allow_list)
        + "<main><table><thead><tr>"
        + "<th>Package</th><th>Version</th><th>Severity</th>"
        + "<th>Confidence</th><th>Findings</th>"
        + "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table></main>"
        + render_allowlisted(allow_list)
        + render_footer()
        + f"<script>{JS}</script>"
        + "</body></html>"
    )


def render_header(timestamp: str) -> str:
    return (
        "<header><h1>wtfguard supply-chain audit</h1>"
        f"<div class=\"meta\">version {__version__} &middot; generated {timestamp}</div></header>"
    )


def render_summary(verdicts: list[Verdict], worst: Severity, allowlisted: list[str]) -> str:
    total = len(verdicts)
    with_findings = sum(1 for v in verdicts if v.findings)
    pill = (
        f"<span class=\"pill\" style=\"background:{SEVERITY_COLOR[worst]}\">"
        f"WORST: {html.escape(worst.label().upper())}</span>"
    )
    return (
        "<section class=\"summary\">"
        f"{pill}"
        f"<span class=\"count\">{total} package{'s' if total != 1 else ''} scanned</span>"
        f"<span class=\"count\">{with_findings} with findings</span>"
        f"<span class=\"count\">{len(allowlisted)} allowlisted</span>"
        "</section>"
    )


def render_row(verdict: Verdict, idx: int) -> str:
    sev = verdict.severity
    color = SEVERITY_COLOR.get(sev, "#666")
    tag = (
        f"<span class=\"tag\" style=\"background:{color}\">{html.escape(sev.label())}</span>"
    )
    findings_count = len(verdict.findings)
    main = (
        f"<tr class=\"clickable\" data-target=\"findings-{idx}\">"
        f"<td><strong>{html.escape(verdict.package)}</strong></td>"
        f"<td>{html.escape(verdict.version)}</td>"
        f"<td>{tag}</td>"
        f"<td>{verdict.confidence:.2f}</td>"
        f"<td>{findings_count}</td>"
        "</tr>"
    )
    if findings_count == 0:
        return main
    inner = "<div class=\"findings-inner\">" + "".join(render_finding(f) for f in verdict.findings)
    if verdict.llm_explanation:
        inner += (
            f"<div class=\"finding\"><div class=\"row\">"
            f"<span class=\"rule\">LLM ({html.escape(verdict.model or '')})</span></div>"
            f"<div class=\"desc\">{html.escape(verdict.llm_explanation)}</div></div>"
        )
    inner += "</div>"
    return main + (
        f"<tr id=\"findings-{idx}\" class=\"findings-row hidden\"><td colspan=\"5\">{inner}</td></tr>"
    )


def render_finding(finding: Finding) -> str:
    color = SEVERITY_COLOR.get(finding.severity, "#666")
    sev_tag = f"<span class=\"tag\" style=\"background:{color}\">{html.escape(finding.severity.label())}</span>"
    return (
        "<div class=\"finding\"><div class=\"row\">"
        f"{sev_tag}"
        f"<span class=\"rule\">{html.escape(finding.rule_id)}</span>"
        f"<span class=\"file\">{html.escape(finding.file)}:{finding.line}</span>"
        "</div>"
        f"<div class=\"desc\">{html.escape(finding.description)}</div>"
        f"<div class=\"desc\" style=\"opacity:0.7\">{html.escape(finding.snippet)}</div>"
        "</div>"
    )


def render_allowlisted(allow_list: list[str]) -> str:
    if not allow_list:
        return ""
    items = "".join(f"<li>{html.escape(s)}</li>" for s in allow_list)
    return f"<main><h3>Allowlisted ({len(allow_list)})</h3><ul>{items}</ul></main>"


def render_footer() -> str:
    return (
        "<footer>wtfguard &mdash; "
        "<a href=\"https://github.com/wachawo/wtfguard\">github.com/wachawo/wtfguard</a>"
        "</footer>"
    )


def worst_severity(verdicts: list[Verdict]) -> Severity:
    if not verdicts:
        return Severity.CLEAN
    return Severity(max(int(v.severity) for v in verdicts))
