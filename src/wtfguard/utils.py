#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small shared helpers.

The single point of truth for PEP 503 package-name normalization. Used by
cache keys, allowlist matching, advisory lookups, and installed-package
deduplication — they must all agree, otherwise an entry like `Zope.Interface`
silently fails to match `zope-interface` in some places and matches in
others.
"""

from __future__ import annotations

import re

PEP503_PATTERN = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    """Apply PEP 503 normalization: lowercase, collapse runs of `_-.` to single `-`.

    >>> normalize_name("Zope.Interface")
    'zope-interface'
    >>> normalize_name("Foo__Bar")
    'foo-bar'
    >>> normalize_name("  django  ")
    'django'
    """
    return PEP503_PATTERN.sub("-", name.strip()).lower()
