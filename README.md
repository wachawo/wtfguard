# wtfguard

> WTF is in this package? Semantic LLM audit for supply-chain attacks in pip/npm/cargo packages.

[![CI](https://github.com/wachawo/wtfguard/actions/workflows/ci.yml/badge.svg)](https://github.com/wachawo/wtfguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

After xz-utils, ultralytics, and lottie-player, every `pip install --upgrade`
is a leap of faith. Snyk and Dependabot catch known CVEs — but zero-day
obfuscation in a fresh release slips through by definition; there's no
signature yet.

`wtfguard` reads the diff between two versions of a PyPI package and runs:

1. **Regex + AST heuristics** — fast, offline, deterministic. Catches network calls
   in setup.py, exec/eval of decoded payloads, large base64 blobs, reads of
   `~/.ssh/` and `~/.aws/`, ctypes / dlopen tricks, subprocess curl/wget,
   custom `cmdclass` install hooks.
2. **LLM audit** (optional) — Claude Haiku (default) or self-host Ollama
   reviews suspicious diffs and returns a JSON verdict with confidence score.

Outputs a verdict: `clean` / `low` / `medium` / `high` / `critical` with exit
codes 0 / 0 / 0 / 1 / 2, so CI can fail builds on `high+` without code changes.

## Status

**Alpha.** This is the public reference implementation. Numbers below are
targets, not measured results — see [the FP-rate philosophy](#false-positive-rate-philosophy).

Phase 1 deliverables shipped in this snapshot:

- [x] PyPI sdist fetcher + extractor (tarbomb-safe)
- [x] Heuristic engine with 8 default rules
- [x] AST-level detection of custom `cmdclass` install hooks
- [x] Local SQLite cache keyed by diff-hash
- [x] Skip-counter / achievement state in `~/.wtfguard/state.json`
- [x] `--talkative` opt-in tip streamer (off by default)
- [x] Optional Claude API integration with prompt caching
- [x] CLI: `scan`, `scan-requirements`, `achievements`, `tip`, `doctor`

- [x] `scan-installed` — discover and audit every package in the active venv
- [x] Allowlist via `.wtfguardignore` / `WTFGUARD_ALLOWLIST` / `~/.wtfguard/allowlist.txt`
- [x] `pyproject.toml` TOML scanner (build hooks, suspicious requires, entry-points)
- [x] GitHub Action template (`action.yml`)
- [x] SARIF 2.1.0 report output for GitHub Code Scanning / GitLab SAST
- [x] Concurrent scanning with `--jobs N` thread pool
- [x] PyPI retry/backoff on 429 / 5xx / transient connection errors
- [x] Ollama backend for self-hosted LLM audit
- [x] Lockfile parsers: `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.in`
- [x] `wtfguard verify` — re-check a cached verdict
- [x] `--json` output on every scan command
- [x] **OSV.dev advisory cross-check** — every scanned (name, version) is queried
  against the OSV.dev database; CVE/GHSA hits surface as `KNOWN_ADVISORY` findings
- [x] **HTML report** (`--html <path>`) — standalone single-file audit report
- [x] **TOML config file** (`~/.wtfguard/config.toml` or `./wtfguard.toml`)
- [x] **`wtfguard bench`** — public FP/FN benchmark on bundled golden fixtures
- [x] **`wtfguard pip install`** — pre-install wrapper around real pip
- [x] **`wtfguard init`** + **`wtfguard rules`** — starter config and rule catalog
- [x] **Custom rules** (`--rules <path>` / `WTFGUARD_RULES` env / `[scan].rules` in config)
- [x] **`[tool.wtfguard]`** section in `pyproject.toml`
- [x] **PEP 503 name normalization** across cache / allowlist / advisory / lockfile
- [x] **`wtfguard explain <rule_id>`** — drill into a single heuristic
- [x] **OSV.dev batch lookup** — single HTTP call for N specs (was N sequential)
- [x] **PyPI metadata signals** — `LOW_RELEASE_COUNT`, `BRAND_NEW_PACKAGE`, `STALE_PACKAGE`, ...
- [x] **`wtfguard show <package>`** — read-only metadata report card without download

Not yet done (Phase 2+):

- [ ] npm and cargo support
- [ ] Pre-install pip hook (currently you wrap install manually)
- [ ] Ollama backend for self-hosted LLM
- [ ] Signed shared cache with M-of-N consensus
- [ ] Public FP-benchmark on top-1000 PyPI
- [ ] SARIF output for enterprise CI

## Install

```bash
pip install wtfguard            # heuristics only, no LLM
pip install 'wtfguard[llm]'     # heuristics + Claude API
```

Source install:

```bash
git clone https://github.com/wachawo/wtfguard
cd wtfguard
pip install -e '.[dev,llm]'
```

## Quick start

Scan a single PyPI package (heuristics only):

```bash
wtfguard scan requests==2.32.0
```

Scan with LLM audit (requires `ANTHROPIC_API_KEY`):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
wtfguard scan ultralytics==8.3.42
```

Scan every pinned dependency in a requirements / lockfile (format auto-detected):

```bash
wtfguard scan-requirements requirements.txt
wtfguard scan-requirements poetry.lock
wtfguard scan-requirements uv.lock
wtfguard scan-requirements Pipfile.lock
wtfguard scan-requirements requirements.txt --json    # machine-readable
```

Scan everything currently installed in the active Python environment:

```bash
wtfguard scan-installed
wtfguard scan-installed --max-packages 20   # limit while iterating
```

Skip known-safe packages by writing a `.wtfguardignore` in the repo root:

```
# .wtfguardignore — committed to the repo
requests
numpy
acme-*                 # any package starting with acme-
internal-utils==1.2.3  # only this exact version
```

Diff scan between two versions:

```bash
wtfguard scan numpy==2.1.0 --base 2.0.0
```

Show one security tip:

```bash
wtfguard tip
```

Inspect runtime state:

```bash
wtfguard doctor
wtfguard achievements
wtfguard rules                  # list every loaded heuristic
wtfguard bench                  # run benchmark on bundled fixtures
wtfguard init                   # drop starter wtfguard.toml + .wtfguardignore
```

Wrap pip so every install is scanned first:

```bash
wtfguard pip install requests==2.32.0 numpy
wtfguard pip install -r requirements.txt --fail-on high
```

Add custom heuristics on top of the bundled set:

```bash
wtfguard rules --rules ./our-team-rules.yaml
wtfguard explain TEAM_INTERNAL_RULE
```

A custom rule file is just a YAML in the same shape as the bundled
`patterns.yaml`. An entry whose `id` matches a built-in **replaces** the
built-in — handy for relaxing or tightening a rule for one team.

```yaml
# our-team-rules.yaml
rules:
  - id: NET_IN_SETUP             # override built-in
    severity: medium             # downgrade from high
    description: Network call in install-script
    file_scope: install_script
    regex: '\b(urlopen|requests\.(get|post))'
  - id: INTERNAL_DEPRECATED_API  # new rule
    severity: low
    description: Use of deprecated internal API
    regex: 'acme\.legacy\.'
```

## Severity tiers

| Severity  | Exit | Default action     | Override        |
|-----------|------|--------------------|-----------------|
| clean     | 0    | silent             | —               |
| low       | 0    | info               | `--quiet`       |
| medium    | 0    | warn               | `--quiet`       |
| high      | 1    | warn + non-zero    | `--no-llm` etc. |
| critical  | 2    | block in CI        | manual review   |

Severity is `max(heuristic_severity, llm_severity)` when the LLM is confident
(>= 0.6). Below the confidence floor, only the heuristic verdict counts —
preventing false positives from a hallucinating model.

## Benchmark

`wtfguard bench` runs the heuristic engine against the bundled
`src/wtfguard/golden/` corpus of safe and malicious fixtures and reports
per-rule TP/FP counts plus overall FP/FN rates. The current shipped
corpus (5 malicious + 3 safe) calibrates to **0% FP / 0% FN at the
HIGH+ severity threshold**.

```
$ wtfguard bench
wtfguard heuristic benchmark
  total fixtures:   8
  safe:             3
  malicious:        5
  true positives:   5
  false positives:  0   (rate 0.0%)
  ...
```

The corpus is intentionally small for v0.1 — `--format markdown` is
designed to be committed to a `benchmarks/` page; the Phase 2 roadmap
expands it to a real top-1000 PyPI shadow benchmark.

## False positive rate philosophy

A security tool that cries wolf gets uninstalled. The single most important
metric for `wtfguard` is **FP-rate on legitimate top-1000 PyPI packages**,
not detection rate on known malware (high detection on bad samples is the
easy part).

- Targets at v1.0: `critical` FP < 0.1%, `high` FP < 1%, `medium` FP < 5%
- A `golden-set` of safe and malicious package fixtures lives in `tests/`
  and runs in CI on every PR
- Each release ships the latest FP-rate on the public benchmark in
  [`CHANGELOG.md`](CHANGELOG.md). No numbers, no release.

If you find a false positive on a popular package, **please open an issue**
with the package name+version. Every report tightens the rules.

## Architecture

```
   heuristics      OSV.dev DB     PyPI metadata    LLM (optional)
   regex+AST       CVE / GHSA     age, releases    Claude / Ollama
   ────────►       ────────►      ──────────►      ──────────►
        │              │              │                  │
        └──────────────┴──────────────┴──────────────────┘
                              ▼
                  severity combiner (confidence-floored)
                              ▼
                  SQLite verdict cache + JSON advisory/metadata cache
                              ▼
                  console / JSON / SARIF / HTML
```

Four detection axes, each independent — the failure of any one does not
block the others.

- `wtfguard.pypi` — fetch and extract release archives
- `wtfguard.diff` — tree diff between two extracted packages
- `wtfguard.heuristics` — regex rules from `data/patterns.yaml` + AST scanner
- `wtfguard.llm` — Anthropic SDK wrapper with prompt caching
- `wtfguard.analyzer` — orchestrator gluing all of the above
- `wtfguard.cache` — SQLite verdict cache with TTL
- `wtfguard.state` — user-local skip/read counters + unlocked achievements

## Comparison

|                          | Snyk        | Socket    | Dependabot | wtfguard     |
|--------------------------|-------------|-----------|------------|--------------|
| Known-CVE feed           | ✓           | ✓         | ✓          | (Phase 4)    |
| Behavioral analysis      | ✗           | ✓         | ✗          | ✓            |
| Semantic **diff** audit  | ✗           | partial   | ✗          | ✓            |
| Open-source core (MIT)   | ✗           | ✗         | ✗          | ✓            |
| Self-host (no cloud)     | enterprise  | ✗         | ✗          | ✓ (Phase 2)  |
| Public FP-benchmark      | ✗           | ✗         | ✗          | planned      |
| Free for solo / OSS      | limited     | limited   | ✓          | ✓ (forever)  |

## Why we exist

Existing tools (Snyk, Socket, Phylum, Dependabot, GitHub Advanced Security)
all rely on **prior knowledge** — either signature feeds or behavior databases.
A patient attacker who studies their detection patterns can ship malware
that passes them all. The xz-utils backdoor is the textbook example: it sat
in tarballs for months before anyone noticed, with no signatures matching.

Semantic diff review by a competent reviewer would have caught xz-utils —
the diff was small, obvious if you looked, and nobody looked. `wtfguard`
makes that reviewer cheap enough to run on every install.

## Talkative mode (opt-in)

`--talkative` streams short security tips, incident retellings, and the
occasional dev-joke during scans. Off by default; you have to opt in
explicitly. A skip counter persists in `~/.wtfguard/state.json` and unlocks
achievements — a small reward for sitting through scans. There is also a
hidden achievement at 1000 skips. We are not going to spoil it.

```bash
wtfguard scan requests --talkative
WTFGUARD_TALKATIVE=1 wtfguard scan-requirements requirements.txt
```

## Self-host LLM (Ollama backend)

For compliance-conscious teams that cannot send package source to a cloud
provider, `wtfguard` supports an Ollama HTTP backend out of the box. No
code change needed — just run Ollama locally and set the env var:

```bash
ollama pull qwen2.5-coder:7b               # or :32b on a beefier machine
export WTFGUARD_LLM_BACKEND=ollama         # explicit
export WTFGUARD_OLLAMA_URL=http://localhost:11434
export WTFGUARD_LLM_MODEL=qwen2.5-coder:7b
wtfguard scan ultralytics==8.3.42
```

When `WTFGUARD_LLM_BACKEND` is unset, wtfguard auto-detects: Claude if
`ANTHROPIC_API_KEY` is present, otherwise Ollama if reachable, otherwise
heuristics-only. `wtfguard doctor` shows which one will fire.

**Honest trade-off:** Qwen 2.5-Coder-7B is meaningfully weaker than
Claude Haiku at catching obfuscation. Use 32B if you have 12+ GB of VRAM.
A formal FP/FN benchmark for each model is on the Phase 2 roadmap —
[track issue](https://github.com/wachawo/wtfguard/issues).

## GitHub Actions

Drop into any workflow:

```yaml
- uses: wachawo/wtfguard@main
  with:
    requirements-file: requirements.txt
    fail-on: high                          # block on high+
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}  # optional
```

Or audit everything installed after a `pip install -e .`:

```yaml
- run: pip install -e .
- uses: wachawo/wtfguard@main
  with:
    scan-installed: 'true'
    jobs: '8'
```

Emit SARIF and upload to GitHub Code Scanning:

```yaml
- uses: wachawo/wtfguard@main
  with:
    requirements-file: requirements.txt
    sarif: wtfguard.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: wtfguard.sarif
```

Full reference: [`examples/github-action.md`](examples/github-action.md).

## Config file

Skip retyping env vars by committing a `wtfguard.toml` at the repo root,
a `[tool.wtfguard]` section in your existing `pyproject.toml`, or a
personal `~/.wtfguard/config.toml`:

```toml
# wtfguard.toml — committed to the repo
[scan]
jobs = 8
no_llm = false
rules = ["our-team-rules.yaml"]

[llm]
backend = "ollama"
model = "qwen2.5-coder:32b"
ollama_url = "http://gpu-host:11434"

[allowlist]
path = ".wtfguardignore"
```

Or inside `pyproject.toml`:

```toml
[tool.wtfguard.scan]
jobs = 8

[tool.wtfguard.llm]
backend = "ollama"
```

Lookup order (first match wins): `WTFGUARD_CONFIG` env, `./wtfguard.toml`,
`./pyproject.toml` (if it has `[tool.wtfguard]`), `~/.wtfguard/config.toml`.
Env vars and CLI flags always win over config.

## Development

```bash
pip install -e '.[dev,llm]'
pytest                          # unit tests
ruff check src tests
mypy src
```

## License

MIT. See [LICENSE](LICENSE).

## Contributing

False positives, missed patterns, ideas, and language-port stubs (npm,
cargo, gem, go mod) are all welcome. Open an issue first to coordinate.

## Project document

The long-form project rationale, market analysis, roadmap, pricing model,
and self-criticism live in [`PROJECT.md`](PROJECT.md). The README is the
*what*; PROJECT.md is the *why*.
