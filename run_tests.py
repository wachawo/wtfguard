#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run wtfguard's test suite without installing the package.

Adds `src/` to `sys.path` so `from wtfguard import ...` resolves, then
invokes pytest. Forwards any CLI args; defaults to a coverage run.

Usage:
    python run_tests.py                          # default coverage run
    python run_tests.py -k heuristics            # filter by keyword
    python run_tests.py tests/test_cli.py        # specific file
    python run_tests.py -v --no-cov              # custom flags
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if SRC.is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DEFAULT_ARGS = ["-ra", "--cov=wtfguard", "--cov-report=term-missing", "--cov-fail-under=80"]


def main() -> int:
    try:
        import pytest
    except ImportError:
        print("error: pytest is not installed — run `pip install pytest pytest-cov`", file=sys.stderr)
        return 1
    return pytest.main(sys.argv[1:] or DEFAULT_ARGS)


if __name__ == "__main__":
    raise SystemExit(main())
