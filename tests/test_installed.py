#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the installed-package discovery module."""

from types import SimpleNamespace
from unittest.mock import patch

from wtfguard.installed import InstalledPackage, list_installed


def fake_dist(name: str, version: str) -> SimpleNamespace:
    return SimpleNamespace(metadata={"Name": name}, version=version)


def test_list_installed_returns_packages() -> None:
    packages = list_installed()
    assert isinstance(packages, list)
    assert all(isinstance(p, InstalledPackage) for p in packages)
    # Our own dev dependencies should be visible
    names = {p.name.lower() for p in packages}
    assert "click" in names or "rich" in names


def test_list_installed_excludes_stdlib_by_default() -> None:
    fakes = [
        fake_dist("pip", "24.0"),
        fake_dist("setuptools", "70.0"),
        fake_dist("requests", "2.32.0"),
    ]
    with patch("wtfguard.installed.metadata.distributions", return_value=fakes):
        packages = list_installed()
    names = {p.name for p in packages}
    assert "pip" not in names
    assert "setuptools" not in names
    assert "requests" in names


def test_list_installed_include_stdlib() -> None:
    fakes = [fake_dist("pip", "24.0"), fake_dist("requests", "2.32.0")]
    with patch("wtfguard.installed.metadata.distributions", return_value=fakes):
        packages = list_installed(include_stdlib=True)
    names = {p.name for p in packages}
    assert "pip" in names
    assert "requests" in names


def test_list_installed_deduplicates_normalized_names() -> None:
    fakes = [fake_dist("Foo_Bar", "1.0"), fake_dist("foo-bar", "1.1")]
    with patch("wtfguard.installed.metadata.distributions", return_value=fakes):
        packages = list_installed()
    assert len(packages) == 1


def test_list_installed_skips_malformed_distributions() -> None:
    bad = SimpleNamespace(metadata={}, version="?")
    good = fake_dist("requests", "2.32.0")
    with patch("wtfguard.installed.metadata.distributions", return_value=[bad, good]):
        packages = list_installed()
    assert [p.name for p in packages] == ["requests"]


def test_list_installed_skips_empty_name() -> None:
    fakes = [fake_dist("", "1.0"), fake_dist("requests", "2.32.0")]
    with patch("wtfguard.installed.metadata.distributions", return_value=fakes):
        packages = list_installed()
    assert [p.name for p in packages] == ["requests"]


def test_list_installed_returns_sorted() -> None:
    fakes = [fake_dist("zoo", "1.0"), fake_dist("alpha", "1.0"), fake_dist("middle", "1.0")]
    with patch("wtfguard.installed.metadata.distributions", return_value=fakes):
        packages = list_installed()
    assert [p.name for p in packages] == ["alpha", "middle", "zoo"]
