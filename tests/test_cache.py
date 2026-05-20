#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the SQLite verdict cache."""

from datetime import timedelta
from pathlib import Path

from wtfguard.cache import VerdictCache
from wtfguard.models import Finding, Severity, Verdict


def build_verdict(diff_hash: str = "abc123") -> Verdict:
    return Verdict(
        package="example",
        version="1.0.0",
        severity=Severity.HIGH,
        confidence=0.85,
        findings=[
            Finding(
                rule_id="NET_IN_SETUP",
                severity=Severity.HIGH,
                file="setup.py",
                line=10,
                snippet="urllib.urlopen('http://x')",
                description="Network call in setup.py",
            )
        ],
        diff_hash=diff_hash,
    )


def test_cache_roundtrip(tmp_path: Path) -> None:
    with VerdictCache(tmp_path / "c.sqlite") as cache:
        cache.put(build_verdict())
        loaded = cache.get("abc123")
        assert loaded is not None
        assert loaded.package == "example"
        assert loaded.severity == Severity.HIGH
        assert len(loaded.findings) == 1
        assert loaded.findings[0].rule_id == "NET_IN_SETUP"


def test_cache_miss_returns_none(tmp_path: Path) -> None:
    with VerdictCache(tmp_path / "c.sqlite") as cache:
        assert cache.get("does-not-exist") is None


def test_cache_expired_entries_filtered(tmp_path: Path) -> None:
    with VerdictCache(tmp_path / "c.sqlite", ttl=timedelta(seconds=0)) as cache:
        cache.put(build_verdict())
        assert cache.get("abc123") is None


def test_cache_overwrites_same_hash(tmp_path: Path) -> None:
    with VerdictCache(tmp_path / "c.sqlite") as cache:
        cache.put(build_verdict())
        replacement = build_verdict()
        replacement.severity = Severity.CRITICAL
        cache.put(replacement)
        loaded = cache.get("abc123")
        assert loaded is not None
        assert loaded.severity == Severity.CRITICAL
