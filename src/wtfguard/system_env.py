#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PEP 668 externally-managed Python environments.

When Python is installed via the system package manager (apt, dnf, brew),
modern distros mark the install with a `EXTERNALLY-MANAGED` marker file.
`pip install` refuses to write into such an interpreter by default — and
`wtfguard pip` should surface that early instead of letting pip fail
cryptically.
"""

from __future__ import annotations

import logging
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

EXTERNAL_MARKER = "EXTERNALLY-MANAGED"


@dataclass(frozen=True)
class EnvironmentReport:
    is_virtualenv:        bool
    is_externally_managed: bool
    marker_path:          Path | None
    python_executable:    str

    def warning_text(self) -> str | None:
        """One-line user-facing warning, or None if no issue."""
        if self.is_externally_managed and not self.is_virtualenv:
            return (
                f"PEP 668: this Python is externally managed ({self.marker_path}). "
                "Use a virtualenv before installing — system pip will refuse."
            )
        return None


def is_in_virtualenv() -> bool:
    """True when running inside a venv / virtualenv / uv-venv."""
    # PEP 405: sys.prefix differs from sys.base_prefix inside a venv.
    if getattr(sys, "base_prefix", sys.prefix) != sys.prefix:
        return True
    # uv and some older virtualenvs set real_prefix.
    return hasattr(sys, "real_prefix")


def externally_managed_marker() -> Path | None:
    """Return the path to the EXTERNALLY-MANAGED marker if it exists, else None."""
    candidates: list[Path] = []
    stdlib = sysconfig.get_path("stdlib")
    if stdlib:
        candidates.append(Path(stdlib).parent / EXTERNAL_MARKER)
    purelib = sysconfig.get_path("purelib")
    if purelib:
        candidates.append(Path(purelib).parent / EXTERNAL_MARKER)
    for path in candidates:
        if path.is_file():
            return path
    return None


def inspect() -> EnvironmentReport:
    """Return the current environment's safety report."""
    virtualenv = is_in_virtualenv()
    marker = externally_managed_marker()
    return EnvironmentReport(
        is_virtualenv=virtualenv,
        is_externally_managed=marker is not None,
        marker_path=marker,
        python_executable=sys.executable,
    )
