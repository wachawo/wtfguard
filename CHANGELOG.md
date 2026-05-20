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
- **`wtfguard bench`** — offline benchmark runner against bundled golden
  fixtures (`src/wtfguard/golden/{safe-*,malicious-*}`). Reports overall
  TP/FP/FN/TN counts plus per-rule activation breakdown. Output formats:
  text, markdown, json. Exit 1 if any FP or FN is observed. The first
  shipped corpus calibrates 5 malicious + 3 safe fixtures with zero
  overall FP/FN — every release ships its bench result in the changelog
- **`wtfguard pip install <specs>`** — pre-install wrapper. Parses pip
  args including `-r requirements`, scans each spec, blocks when worst
  severity meets `--fail-on` threshold (default critical). On `high`
  prompts for confirmation unless `--yes`. Delegates non-`install`
  subcommands straight to pip
- **`wtfguard rules`** — list every loaded heuristic rule with id,
  severity, file scope, description. `--format json` for tooling
- **`wtfguard init`** — drops a starter `wtfguard.toml` and
  `.wtfguardignore` in the cwd (or `--dir`). `--force` to overwrite
- 319 tests, 95.62% line coverage
- **Custom rules YAML** — `--rules <path>` flag (repeatable) on `rules`,
  `explain` commands, `WTFGUARD_RULES` env var (os.pathsep-separated),
  and `[scan].rules` in config. Custom rule id matching a bundled one
  replaces it — letting teams tighten or relax built-ins. Bad regex /
  missing file degrade gracefully
- **`[tool.wtfguard]` in pyproject.toml** — config loader recognises this
  TOML section in addition to `wtfguard.toml` and `~/.wtfguard/config.toml`.
  Discovery order: `WTFGUARD_CONFIG` env, `./wtfguard.toml`,
  `./pyproject.toml` (if it has the section), then home
- **PEP 503 name normalization** — new `wtfguard.utils.normalize_name`
  collapses runs of `_`, `-`, `.` to a single dash and lowercases.
  Single source of truth used by `allowlist`, `lockfile`, `installed`,
  and `advisory` lookup keys
- **`wtfguard explain <rule_id>`** — print a rule's id, severity, scope,
  regex, and description in a Rich panel. Case-insensitive id matching
- 346 tests, 95.57% line coverage
- **OSV.dev batch lookup** — new `advisory.lookup_batch` posts all
  cache-miss queries to `https://api.osv.dev/v1/querybatch` in a single
  HTTP roundtrip. Cuts `scan-installed` advisory latency on a 50-package
  venv from ~50 sequential queries to 1
- **PyPI metadata signals** — new `wtfguard.pypi_signals` module adds a
  fourth detection axis on top of heuristics + OSV + LLM. Without
  downloading the package, derives findings from PyPI JSON metadata:
  `LOW_RELEASE_COUNT`, `BRAND_NEW_PACKAGE` (medium — typosquat candidate),
  `STALE_PACKAGE`, `MISSING_PROJECT_URL`, `SINGLE_FILE_RELEASE`. 24h cache
  at `~/.wtfguard/pypi-metadata-cache.json`
- **`wtfguard show <package>`** — read-only metadata report card.
  Pretty-print + `--json`. Shows latest version, summary, release dates,
  file count, project URLs, derived metadata signals, and known OSV
  advisories. No download, no heuristic scan — use for fast triage
- `AnalysisOptions.use_metadata` toggle (default true). conftest autouse
  fixture stubs the metadata fetcher so tests stay offline
- 378 tests, 94.39% line coverage
- **Typosquat detection** — fifth detection axis. New `wtfguard.typosquat`
  module compares package name against a bundled top-~100 PyPI list
  (`src/wtfguard/data/popular_pypi.txt`) via Levenshtein. Names within
  edit distance 1 of a popular package fire `TYPOSQUAT_CANDIDATE` at
  **high** severity, distance 2 at **medium**. Exact matches are never
  flagged. Short names (≤4 chars) are skipped to avoid noise. Toggle
  via `AnalysisOptions.use_typosquat`
- **Markdown report** (`--markdown <path>`) — third report format
  alongside SARIF and HTML. CommonMark with collapsible `<details>` per
  package and severity-emoji table for fast skim. Designed to be pasted
  into a GitHub PR comment
- **`wtfguard watch <file>`** — file-watching dev loop. Polls mtime
  (no inotify dependency), re-runs scan on every change. Ideal for
  editing `requirements.txt` / `poetry.lock` with the verdict open in
  another pane. Handles Ctrl-C gracefully, clamps interval to 30s,
  catches callback exceptions
- 416 tests, 93.92% line coverage
- **CycloneDX 1.5 SBOM output** (`--cyclonedx <path>`) — sixth report
  format. Maps each verdict to a CycloneDX `component` (with PURL),
  surfaces `KNOWN_ADVISORY` findings as `vulnerabilities`, and stashes
  other findings under `component.properties` so OWASP Dependency-Track,
  GitLab SBOM upload, AWS Inspector, etc. don't lose them
- **Confusable substitution in typosquat** — `wtfguard.typosquat`
  now generates visually-confusable variants of each candidate
  (`0`↔`o`, `1`↔`l`, `5`↔`s`, `rn`↔`m`, `cl`↔`d`, `vv`↔`w`) and runs
  Levenshtein against each. Catches attacks where the swap is more than
  `max_distance` raw edits, e.g. `modem-pkg` vs `modern-pkg`
- **`wtfguard diff <before.json> <after.json>`** — compare two scan
  outputs (single-scan or batch). Reports added findings, removed
  findings, severity changes, and worst-severity delta. Exits 1 on any
  change, useful for upgrade-audit CI gates. `--json` for tooling
- 449 tests, 93.35% line coverage
