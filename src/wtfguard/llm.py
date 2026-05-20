#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Optional Claude API integration for semantic diff audit.

Behaviour:
- If `ANTHROPIC_API_KEY` is unset or the `anthropic` package is not installed,
  the LLM stage is silently skipped and the verdict comes from heuristics alone.
- The system prompt (rule catalog) is large and stable — cache_control breakpoint
  is set on it so repeated scans hit the prompt cache.
"""

import json
import logging
import os
import re
from dataclasses import dataclass

from wtfguard.heuristics import Rule
from wtfguard.models import Severity

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv("WTFGUARD_LLM_MODEL", "claude-haiku-4-5-20251001")
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.0
MAX_DIFF_CHARS = 60_000


@dataclass(frozen=True)
class LlmVerdict:
    severity: Severity
    confidence: float
    explanation: str
    model: str


def is_available() -> bool:
    if not os.getenv("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def build_system_prompt(rules: list[Rule]) -> str:
    rule_lines = [
        f"- {r.id} ({r.severity.label()}): {r.description}"
        for r in sorted(rules, key=lambda r: (-int(r.severity), r.id))
    ]
    return (
        "You are wtfguard, a security auditor for Python package diffs.\n"
        "You read unified diffs between two versions of a PyPI package and decide whether\n"
        "the changes look malicious. Be conservative: flag only patterns you can justify.\n\n"
        "Known heuristic categories (regex prefilter already ran; you see only suspicious diffs):\n"
        + "\n".join(rule_lines)
        + "\n\nReturn ONLY a single JSON object on one line, no prose, no code fences:\n"
        "{\n"
        '  "severity": "clean" | "low" | "medium" | "high" | "critical",\n'
        '  "confidence": float in [0, 1],\n'
        '  "explanation": string (max 400 chars, plain text)\n'
        "}\n"
        "Confidence below 0.6 means you would like a human reviewer to double-check."
    )


def build_user_prompt(package: str, version: str, diff_text: str) -> str:
    truncated = diff_text[:MAX_DIFF_CHARS]
    note = "" if len(diff_text) <= MAX_DIFF_CHARS else f"\n\n[diff truncated to {MAX_DIFF_CHARS} chars]"
    return (
        f"Package: {package}\n"
        f"Version: {version}\n\n"
        f"Diff:\n```\n{truncated}\n```{note}"
    )


def parse_response(text: str) -> LlmVerdict | None:
    """Extract the JSON verdict from the model's reply. Returns None if unparseable."""
    candidate = text.strip()
    match = re.search(r"\{.*\}", candidate, re.DOTALL)
    if match is None:
        logger.warning(f"LLM reply contained no JSON object: {text[:200]}")
        return None
    try:
        data = json.loads(match.group(0))
        severity = Severity.from_name(str(data["severity"]))
        confidence = float(data["confidence"])
        explanation = str(data.get("explanation", ""))[:400]
        return LlmVerdict(
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            explanation=explanation,
            model="",
        )
    except (KeyError, ValueError) as exc:
        logger.warning(f"LLM reply parse failed: {type(exc).__name__}: {exc}; raw={text[:200]}")
        return None


def audit_diff(
    package: str,
    version: str,
    diff_text: str,
    rules: list[Rule],
    model: str = DEFAULT_MODEL,
) -> LlmVerdict | None:
    """Send the diff to Claude. Returns None when the LLM stage is unavailable or fails."""
    if not is_available():
        logger.info("LLM stage skipped (no ANTHROPIC_API_KEY or anthropic package missing)")
        return None

    import anthropic

    client = anthropic.Anthropic()
    system_prompt = build_system_prompt(rules)
    user_prompt = build_user_prompt(package, version, diff_text)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=DEFAULT_MAX_TOKENS,
            temperature=DEFAULT_TEMPERATURE,
            system=[
                {
                    "type":          "text",
                    "text":          system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_prompt}],
        )
    except Exception as exc:
        logger.error(f"LLM call failed: {type(exc).__name__}: {exc}")
        return None

    reply_text = ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            reply_text += block.text

    verdict = parse_response(reply_text)
    if verdict is None:
        return None
    return LlmVerdict(
        severity=verdict.severity,
        confidence=verdict.confidence,
        explanation=verdict.explanation,
        model=model,
    )
