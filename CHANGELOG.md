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
- 159 unit tests, 95% line coverage, CI gate at 80%
- Anthropic SDK call path covered via mocked `anthropic.Anthropic` client
- `wtfguard scan-installed` — discover packages via `importlib.metadata`
  and scan every entry in the active Python environment
- Allowlist support — `.wtfguardignore` (cwd) / `WTFGUARD_ALLOWLIST` env /
  `~/.wtfguard/allowlist.txt`. Supports bare names, pinned `name==version`,
  and glob prefixes (`acme-*`). `--allowlist` flag overrides discovery
- `pyproject.toml` TOML-aware scanner: flags URL/path entries in
  `build-system.requires`, unknown `build-backend`, custom build hooks in
  `[tool.<name>.hooks]`, Poetry `post_install*` scripts, and entry-point
  groups suggesting install-time execution
- `action.yml` — reusable GitHub Action (`uses: wachawo/wtfguard@main`)
  with `requirements-file` / `scan-installed` / `fail-on` inputs
- **SARIF 2.1.0 output** (`--sarif <path>`) — emits a report consumable
  by GitHub Code Scanning, GitLab SAST, Azure DevOps, and any tool that
  speaks SARIF. Action gained matching `sarif:` input
- **Concurrent scanning** (`--jobs N`, default 4) — `scan-requirements`
  and `scan-installed` now use a thread pool. Order of results is stable
- **Network retry/backoff** — PyPI requests automatically retry on
  429 / 5xx and transient ConnectionError / Timeout (3 attempts, exponential
  backoff). Last response is returned if all retries return 5xx
- 186 tests, 95% line coverage
- **Ollama backend** for self-hosted LLM audit. Auto-detects when Claude
  is unavailable; switch with `WTFGUARD_LLM_BACKEND=ollama`. Configurable
  via `WTFGUARD_OLLAMA_URL` (default `http://localhost:11434`) and
  `WTFGUARD_LLM_MODEL` (default `qwen2.5-coder:7b`). Speaks the `/api/chat`
  endpoint with `format: json`
- **Lockfile parsers** — `scan-requirements` auto-detects format by
  filename: `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt`,
  `requirements.in`. Duplicates are removed by case-insensitive
  name+version key
- **`wtfguard verify <package>`** — re-runs analysis, compares against
  the cached verdict for the same diff-hash. Exit 0 on match, 1 on
  divergence, 2 on lookup error. Foundation for the Phase 3 signed
  shared cache
- **`--json` for `scan-requirements` and `scan-installed`** — emits
  `{verdicts: [...], allowlisted: [...], worst: <severity>}`. Closes the
  asymmetry where only single `scan` had JSON output
- `doctor` now shows the active backend, model, and Ollama URL
- 227 tests, 95% line coverage
- **OSV.dev advisory lookup** — new `wtfguard.advisory` module queries the
  public OSV.dev API for known CVE/GHSA on every scanned (name, version).
  Hits are surfaced as `KNOWN_ADVISORY` findings with severity derived from
  CVSS score (>=9 critical, >=7 high, >=4 medium, >0 low). Results are
  cached in `~/.wtfguard/advisory-cache.json` with 24h TTL.
  `analyzer.AnalysisOptions.use_advisory` toggles the stage
- **HTML report** (`--html <path>`) — standalone single-file HTML5 with
  embedded CSS/JS, summary pill, drill-down findings per package. No
  external assets — emails clean, opens offline
- **TOML config file** — `wtfguard.toml` in cwd, `WTFGUARD_CONFIG` env, or
  `~/.wtfguard/config.toml`. Sections `[scan]`, `[llm]`, `[allowlist]`.
  Values project into env vars only if the env var is not already set
  (env/CLI always win)
- 274 tests, 95% line coverage
