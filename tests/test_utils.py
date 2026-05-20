#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for PEP 503 name normalization helpers."""

from wtfguard.utils import normalize_name


def test_lowercase() -> None:
    assert normalize_name("Django") == "django"
    assert normalize_name("REQUESTS") == "requests"


def test_underscore_to_dash() -> None:
    assert normalize_name("foo_bar") == "foo-bar"
    assert normalize_name("Foo_Bar_Baz") == "foo-bar-baz"


def test_dot_to_dash() -> None:
    assert normalize_name("zope.interface") == "zope-interface"
    assert normalize_name("zope.interface.adapter") == "zope-interface-adapter"


def test_collapses_runs() -> None:
    assert normalize_name("Foo__Bar") == "foo-bar"
    assert normalize_name("foo--bar") == "foo-bar"
    assert normalize_name("foo-_-bar") == "foo-bar"


def test_strip_whitespace() -> None:
    assert normalize_name("  django  ") == "django"


def test_idempotent() -> None:
    once = normalize_name("Foo_Bar")
    twice = normalize_name(once)
    assert once == twice


def test_mixed_chars() -> None:
    assert normalize_name("Zope.Interface_Adapter--Plugin") == "zope-interface-adapter-plugin"


def test_no_change_already_normal() -> None:
    assert normalize_name("requests") == "requests"
    assert normalize_name("foo-bar") == "foo-bar"
