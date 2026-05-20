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

Scan every pinned dependency in a requirements file:

```bash
wtfguard scan-requirements requirements.txt
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
   ┌──────────────┐    ┌────────────┐    ┌──────────────┐
   │  PyPI sdist  │───►│  Heuristics│───►│  LLM (opt.)  │
   │   fetcher    │    │  regex+AST │    │  Claude API  │
   └──────────────┘    └─────┬──────┘    └──────┬───────┘
                             │                  │
                             ▼                  ▼
                       ┌─────────────────────────┐
                       │   Severity combiner     │
                       │   (confidence-floored)  │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │  SQLite verdict cache   │
                       │  keyed by diff-hash     │
                       └────────────┬────────────┘
                                    │
                                    ▼
                              CLI verdict
```

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

## Self-host LLM (Phase 2)

For compliance-conscious teams that cannot send package source to a cloud
provider, `wtfguard` will support an Ollama HTTP backend. Configuration:

```toml
# ~/.wtfguard/config.toml
[llm]
backend = "ollama"
endpoint = "http://localhost:11434"
model = "qwen2.5-coder:32b"
```

Quality versus Claude Haiku will be **honestly benchmarked** in the README
when the backend ships. Smaller self-host models miss more obfuscation;
that trade-off is your call, not hidden.

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
```

Full reference: [`examples/github-action.md`](examples/github-action.md).

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
