# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial CLI skeleton: `wtfguard scan <package>` command
- Regex heuristics engine with 8 default patterns (network in setup.py, exec/eval, base64-blobs, SSH/AWS credential reads, ctypes/dlopen, subprocess curl/wget, obfuscated imports, suspicious post-install)
- AST-based detectors for setup.py / pyproject.toml
- PyPI sdist downloader and extractor
- Severity tier with configurable thresholds (clean / low / medium / high / critical)
- Local SQLite cache by diff-hash (`~/.wtfguard/cache.sqlite`)
- Skip-counter and achievement state in `~/.wtfguard/state.json`
- Tips streamer with `--talkative` opt-in mode (off by default)
- Optional Claude API integration via `ANTHROPIC_API_KEY` env var with prompt caching for the patterns system prompt
- Golden-set fixture for FP-benchmark (`tests/golden/`)
- GitHub Actions CI: ruff + mypy + pytest on Python 3.11 / 3.12 / 3.13
- Per-source-file test suite: one `test_*.py` per module in `src/wtfguard/`
- 122 unit tests, 95% line coverage, CI gate at 80%
- Anthropic SDK call path covered via mocked `anthropic.Anthropic` client
