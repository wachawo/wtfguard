#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the LLM module (no real network — anthropic client is mocked)."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from wtfguard.heuristics import load_rules
from wtfguard.llm import (
    audit_diff,
    build_system_prompt,
    build_user_prompt,
    is_available,
    parse_response,
)
from wtfguard.models import Severity


def test_parse_clean_response() -> None:
    text = '{"severity": "clean", "confidence": 0.95, "explanation": "no issues"}'
    v = parse_response(text)
    assert v is not None
    assert v.severity == Severity.CLEAN
    assert v.confidence == 0.95


def test_parse_response_inside_prose() -> None:
    text = 'Here is my verdict:\n{"severity": "high", "confidence": 0.7, "explanation": "x"}\n'
    v = parse_response(text)
    assert v is not None
    assert v.severity == Severity.HIGH


def test_parse_response_clamps_confidence() -> None:
    text = '{"severity": "medium", "confidence": 1.7, "explanation": "x"}'
    v = parse_response(text)
    assert v is not None
    assert v.confidence == 1.0

    text2 = '{"severity": "medium", "confidence": -0.5, "explanation": "x"}'
    v2 = parse_response(text2)
    assert v2 is not None
    assert v2.confidence == 0.0


def test_parse_response_invalid_json_returns_none() -> None:
    assert parse_response("not json") is None
    assert parse_response('{"severity": "bogus", "confidence": 0.5}') is None


def test_parse_response_truncates_explanation() -> None:
    long_text = "x" * 1000
    text = f'{{"severity": "low", "confidence": 0.5, "explanation": "{long_text}"}}'
    v = parse_response(text)
    assert v is not None
    assert len(v.explanation) == 400


def test_build_system_prompt_lists_rules() -> None:
    rules = load_rules()
    prompt = build_system_prompt(rules)
    assert "wtfguard" in prompt
    assert "JSON" in prompt
    for r in rules:
        assert r.id in prompt


def test_build_user_prompt_truncates_large_diffs() -> None:
    huge = "x" * 200_000
    prompt = build_user_prompt("demo", "1.0.0", huge)
    assert "diff truncated" in prompt
    assert "demo" in prompt


def test_build_user_prompt_short_diff_not_truncated() -> None:
    prompt = build_user_prompt("demo", "1.0.0", "small diff")
    assert "diff truncated" not in prompt


def test_is_available_false_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert is_available() is False


def test_is_available_false_without_anthropic_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    original = sys.modules.pop("anthropic", None)
    monkeypatch.setitem(sys.modules, "anthropic", None)
    try:
        assert is_available() is False
    finally:
        if original is not None:
            sys.modules["anthropic"] = original


def test_audit_diff_returns_none_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = audit_diff("demo", "1.0.0", "diff", load_rules())
    assert result is None


def test_audit_diff_parses_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    fake_block = SimpleNamespace(type="text", text='{"severity":"high","confidence":0.9,"explanation":"net"}')
    fake_response = SimpleNamespace(content=[fake_block])

    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response

    fake_anthropic = SimpleNamespace(Anthropic=MagicMock(return_value=fake_client))

    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = audit_diff("demo", "1.0.0", "diff body", load_rules(), model="test-model")

    assert result is not None
    assert result.severity == Severity.HIGH
    assert result.confidence == 0.9
    assert result.model == "test-model"

    call_kwargs = fake_client.messages.create.call_args.kwargs
    assert call_kwargs["model"] == "test-model"
    assert call_kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_audit_diff_handles_unparseable_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    fake_block = SimpleNamespace(type="text", text="not json at all")
    fake_response = SimpleNamespace(content=[fake_block])
    fake_client = MagicMock()
    fake_client.messages.create.return_value = fake_response
    fake_anthropic = SimpleNamespace(Anthropic=MagicMock(return_value=fake_client))

    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = audit_diff("demo", "1.0.0", "diff", load_rules())
    assert result is None


def test_audit_diff_handles_api_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    fake_client = MagicMock()
    fake_client.messages.create.side_effect = RuntimeError("api down")
    fake_anthropic = SimpleNamespace(Anthropic=MagicMock(return_value=fake_client))

    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = audit_diff("demo", "1.0.0", "diff", load_rules())
    assert result is None
