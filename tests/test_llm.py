#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the LLM response parser (no network)."""

from wtfguard.llm import parse_response
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
