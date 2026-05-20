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
- **License compliance check** — sixth detection axis. Reads
  `info.license` and `License ::`-style classifiers from PyPI metadata,
  matches against a default permissive allowlist (MIT, Apache-2.0, BSD-*,
  ISC, MPL-2.0, ...). Non-allowed licenses fire `LICENSE_INCOMPATIBLE`
  (medium). Missing license fires `LICENSE_UNKNOWN` (low). Multi-license
  expressions (`MIT OR Apache-2.0`) pass if any side is allowed.
  Toggleable via `AnalysisOptions.use_license_check` and the
  `allowed_licenses` override
- **`wtfguard verify-baseline <baseline.json>`** — re-scan the same
  packages a baseline JSON pinned, diff against it, exit 1 on any
  drift. Workflow: commit a clean baseline to the repo, CI fails the
  PR build when a finding appears or severity changes. `--json` for
  machine output
- **PEP 668 system-managed environment detection** — new
  `wtfguard.system_env` checks for `EXTERNALLY-MANAGED` marker.
  `wtfguard doctor` surfaces virtualenv status and warns when running
  against a system Python that pip would refuse to write into.
  `wtfguard pip install` flow prints the same warning before delegating
- 482 tests, 92.57% line coverage
- **Append-only audit log** — new `wtfguard.audit_log` module writes one
  JSON line per scan to `~/.wtfguard/audit.log.jsonl` (override via
  `WTFGUARD_AUDIT_LOG` env, skip via `WTFGUARD_AUDIT_DISABLED=1`).
  Wired into `scan`, `scan-requirements`, `scan-installed`. Includes
  `read_entries`, `prune_older_than(days)` helpers for compliance
  rotation
- **Plugin entry-points** — new `wtfguard.plugins` discovers third-party
  rule packs via `[project.entry-points."wtfguard.rules"]`. Each plugin
  may declare a callable or a YAML path; `heuristics.load_rules` merges
  them with bundled rules. Broken plugins are logged and skipped — they
  never break wtfguard. Pass `include_plugins=False` to opt out
- **Unicode confusable typosquats** — typosquat axis now de-Unicodes
  candidate names before Levenshtein. Catches Cyrillic / Greek
  homoglyph attacks where `rеquеsts` (Cyrillic 'е') looks identical to
  Latin `requests`. Also normalises dash lookalikes (en-dash, em-dash,
  non-breaking hyphen) to ASCII `-`
- 513 tests, 92.41% line coverage
- **`wtfguard bench --network`** — shadow-bench against the top-N real
  PyPI packages. Fetches the live top-PyPI list and runs heuristics-only
  analysis (no LLM, no advisory, no metadata, no typosquat, no license —
  pure static checks) on each. Reports flagged-high count and the
  implicit FP-rate on assumed-legitimate populars. Exits 1 if any HIGH+
  finding fires. `--top N` overrides the default 50
- **`wtfguard scan-dir <path>`** — scan a local source tree without any
  PyPI fetch. Same heuristic engine (regex + AST + pyproject.toml +
  custom rules) but offline. Use as a pre-publish self-audit: catch
  what wtfguard would catch on your own package before you upload
- **`wtfguard audit-log` command group** — `show` lists recent
  audit-log entries with `--limit / --severity / --command / --json`
  filters; `prune --days N --yes` drops old entries
- 541 tests, 92.74% line coverage
- **`wtfguard refresh-popular`** — re-fetch the top-N PyPI list and
  rewrite the bundled typosquat dictionary. `--top N` (default 500),
  `--output <path>` for custom target, `--dry-run` to preview. Uses
  the same upstream as `bench --network`
- **`wtfguard audit-log stats`** — summary view of the audit log:
  total entries and distribution by severity and command. `--json` for
  machine consumption
- **`wtfguard pre-commit-config`** — print a starter
  `.pre-commit-config.yaml` snippet. `--include-requirements` also
  wires up the `scan-requirements` hook
- **Bundled `.pre-commit-hooks.yaml`** — repo now ships native
  pre-commit hook definitions (`wtfguard-scan-dir`,
  `wtfguard-scan-requirements`, `wtfguard-verify-baseline`) so users
  can add wtfguard via a one-line `pre-commit-config.yaml` referencing
  this repository
- 555 tests, 92.88% line coverage
- **PyPI sdist SHA256 verification** — `pypi.download_file` now compares
  the downloaded artifact against the `info.digests.sha256` PyPI publishes
  in its JSON metadata. Raises `OSError` on mismatch. Catches MITM
  tampering and wrong-mirror configurations where the body and metadata
  diverge. Releases without a published sha256 skip verification
- **`LOW_DOWNLOAD_VOLUME` signal** — new optional `pypi_signals` rule.
  Pulls last-30-day download count from `pypistats.org/api/packages/...`,
  fires LOW when below 1000 downloads/month — typosquat / abandoned /
  brand-new indicator
- **`wtfguard cache` command group** — `stats` shows sizes of the
  SQLite verdict cache + JSON advisory + JSON metadata caches.
  `clear --verdict/--advisory/--metadata/--all --yes` deletes them
- **`wtfguard completion {bash,zsh,fish}`** — emits shell-completion
  scripts via Click's `_WTFGUARD_COMPLETE` env var. Pipe into your
  shell's completion directory for tab-completion of subcommands and
  flags
- 579 tests, 92.73% line coverage
- **`wtfguard scan-tree <package>`** — resolve transitive dependency
  tree via `requires_dist` parsing and scan every node. New module
  `wtfguard.dependency_tree` walks PEP 508 requirements (skipping
  extras and unmatched environment markers), capped at `--max-depth`
  (default 3) and `--max-nodes` (default 200). `--tree-only` just
  prints the resolved tree without scanning. Closes the
  direct-deps-only gap — most supply-chain attacks ride in transitive
  packages
- **PEP 740 attestation surfacing** — `pypi_signals.PackageMetadata`
  gains `has_attestations` and `attestation_count` fields, populated
  from per-file `attestations` arrays in PyPI JSON. `wtfguard show`
  displays the attestation status (Trusted Publisher / OIDC signing)
  in both text and JSON output. Informational only — no rule fires
  yet because PEP 740 adoption is still rolling out
- **`wtfguard config show`** — print the effective configuration
  resolved from `wtfguard.toml` / `pyproject.toml` / `WTFGUARD_CONFIG`
  / `~/.wtfguard/config.toml`, plus every wtfguard-relevant env var
  with set/unset status. `--json` for machine consumption
- 608 tests, 92.80% line coverage
- **YAML policy file** (`--policy <path>`) — new `wtfguard.policy` module
  loads severity overrides per rule and per package. Supports
  `severity: ignore` to drop findings entirely. Discovery chain:
  explicit flag, `WTFGUARD_POLICY` env, `./wtfguard-policy.yaml`.
  Applied post-scan via `policy.apply()` so the verdict's overall
  severity is recomputed from surviving findings
- **Webhook notification** (`--webhook <url>`) — new `wtfguard.webhook`
  module POSTs a scan summary to Slack / Discord / generic JSON
  endpoints. Format auto-detected from URL (`hooks.slack.com` →
  Slack, `discord(app).com` → Discord, otherwise raw JSON), override
  via `WTFGUARD_WEBHOOK_FORMAT`
- **`--offline` mode** — `AnalysisOptions.offline=True` is shorthand
  for disabling every network-dependent stage (LLM + advisory +
  metadata). Heuristics, typosquat, and license_check keep running.
  Exposed as `--offline` on both batch scan commands
- 643 tests, 92.79% line coverage
- **`wtfguard incident <package>`** — forensic timeline interleaving
  PyPI release dates with known OSV advisories. New module
  `wtfguard.incident` builds chronologically-sorted events answering
  "when did the vulnerable version ship, when was the CVE disclosed,
  when did the fix arrive". Text and `--json` output
- **`wtfguard prefetch <requirements>`** — pre-download every pinned
  sdist into a target directory (default `~/.wtfguard/prefetch`) so a
  later `--offline` scan has the cache it needs. Uses existing
  `pypi.download_file` with SHA256 verification. Reports
  succeeded / skipped / failed per spec
- **`wtfguard policy-cli show / validate`** — companion commands for
  the YAML policy file. `show` displays the loaded policy
  (auto-discovers a file when none given). `validate` parses, lists
  overrides, and flags unknown rule IDs that will never fire
- 669 tests, 92.96% line coverage
- **`wtfguard threats`** — proactive threat-intel scan. Walks every
  installed package, queries OSV.dev in batch, and prints any known
  advisories with severity, advisory id, and summary. `--since 7d|24h|2w`
  windowing, `--min-severity` filter, `--include-stdlib`, `--json`.
  Exits 1 if any threat is found
- **`--min-severity LEVEL`** on `scan-requirements` and `scan-installed`
  — drops verdicts below the threshold from both human output and
  exit-code computation. Useful pairing with policy file overrides
- **`wtfguard policy-cli init`** — scaffolds a starter
  `wtfguard-policy.yaml` with commented examples (downgrade
  `NET_IN_SETUP` for an internal package, drop `LICENSE_INCOMPATIBLE`,
  raise `BRAND_NEW_PACKAGE`). `--force` to overwrite, `--output` for
  custom target
- 688 tests, 93.08% line coverage
