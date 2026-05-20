#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM backend dispatcher: Anthropic Claude (cloud) or Ollama (self-host).

Backend is chosen by `WTFGUARD_LLM_BACKEND` env var:
- "claude" (default if ANTHROPIC_API_KEY is set)
- "ollama" (default if no API key; uses WTFGUARD_OLLAMA_URL, default http://localhost:11434)

If `WTFGUARD_LLM_BACKEND` is unset, auto-detection picks the first available.
If nothing is available, `audit_diff()` returns None and the heuristic verdict
stands alone.

The system prompt (rule catalog) is large and stable — Claude path sets a
`cache_control` breakpoint on it so repeated scans hit Anthropic's prompt cache.
Ollama has no equivalent cache so prompt size matters more there.
"""

import json
import logging
import os
import re
from dataclasses import dataclass

import requests

from wtfguard.heuristics import Rule
from wtfguard.models import Severity

logger = logging.getLogger(__name__)

DEFAULT_CLAUDE_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.0
MAX_DIFF_CHARS = 60_000
OLLAMA_PING_TIMEOUT = 1.5
OLLAMA_REQUEST_TIMEOUT = 120

BACKEND_CLAUDE = "claude"
BACKEND_OLLAMA = "ollama"
VALID_BACKENDS = frozenset({BACKEND_CLAUDE, BACKEND_OLLAMA})


@dataclass(frozen=True)
class LlmVerdict:
    severity:    Severity
    confidence:  float
    explanation: str
    model:       str


def configured_backend() -> str | None:
    """Return the user-requested backend, normalised. None means autodetect."""
    raw = os.getenv("WTFGUARD_LLM_BACKEND", "").strip().lower()
    if not raw:
        return None
    if raw not in VALID_BACKENDS:
        logger.warning(f"Unknown WTFGUARD_LLM_BACKEND={raw!r}; falling back to autodetect")
        return None
    return raw


def active_backend() -> str | None:
    """Resolve the backend that audit_diff will actually use, or None if none is available."""
    requested = configured_backend()
    if requested == BACKEND_CLAUDE:
        return BACKEND_CLAUDE if claude_available() else None
    if requested == BACKEND_OLLAMA:
        return BACKEND_OLLAMA if ollama_available() else None
    if claude_available():
        return BACKEND_CLAUDE
    if ollama_available():
        return BACKEND_OLLAMA
    return None


def claude_available() -> bool:
    if not os.getenv("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def ollama_available() -> bool:
    url = ollama_url()
    try:
        resp = requests.get(f"{url}/api/tags", timeout=OLLAMA_PING_TIMEOUT)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False
    except Exception as exc:
        logger.debug(f"Ollama probe failed: {type(exc).__name__}: {exc}")
        return False


def is_available() -> bool:
    """Backwards-compatible: any LLM backend reachable."""
    return active_backend() is not None


def ollama_url() -> str:
    return os.getenv("WTFGUARD_OLLAMA_URL", DEFAULT_OLLAMA_URL).rstrip("/")


def default_model_for(backend: str) -> str:
    override = os.getenv("WTFGUARD_LLM_MODEL")
    if override:
        return override
    return DEFAULT_OLLAMA_MODEL if backend == BACKEND_OLLAMA else DEFAULT_CLAUDE_MODEL


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
    model: str | None = None,
) -> LlmVerdict | None:
    """Dispatch to the active LLM backend. Returns None when none is available or call fails."""
    backend = active_backend()
    if backend is None:
        logger.info("LLM stage skipped (no Claude key, no reachable Ollama)")
        return None

    chosen_model = model or default_model_for(backend)
    system_prompt = build_system_prompt(rules)
    user_prompt = build_user_prompt(package, version, diff_text)

    if backend == BACKEND_CLAUDE:
        return claude_audit_diff(system_prompt, user_prompt, chosen_model)
    return ollama_audit_diff(system_prompt, user_prompt, chosen_model)


def claude_audit_diff(system_prompt: str, user_prompt: str, model: str) -> LlmVerdict | None:
    import anthropic

    client = anthropic.Anthropic()
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
        logger.error(f"Claude call failed: {type(exc).__name__}: {exc}")
        return None

    reply_text = ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            reply_text += block.text

    parsed = parse_response(reply_text)
    if parsed is None:
        return None
    return LlmVerdict(
        severity=parsed.severity,
        confidence=parsed.confidence,
        explanation=parsed.explanation,
        model=model,
    )


def ollama_audit_diff(system_prompt: str, user_prompt: str, model: str) -> LlmVerdict | None:
    url = f"{ollama_url()}/api/chat"
    payload = {
        "model":   model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "format":  "json",
        "stream":  False,
        "options": {"temperature": DEFAULT_TEMPERATURE, "num_predict": DEFAULT_MAX_TOKENS},
    }
    try:
        resp = requests.post(url, json=payload, timeout=OLLAMA_REQUEST_TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:
        logger.error(f"Ollama call failed: {type(exc).__name__}: {exc}")
        return None

    reply_text = ""
    message = body.get("message") or {}
    if isinstance(message, dict):
        reply_text = str(message.get("content", ""))
    if not reply_text:
        reply_text = str(body.get("response", ""))

    parsed = parse_response(reply_text)
    if parsed is None:
        return None
    return LlmVerdict(
        severity=parsed.severity,
        confidence=parsed.confidence,
        explanation=parsed.explanation,
        model=model,
    )


DEFAULT_MODEL = DEFAULT_CLAUDE_MODEL
