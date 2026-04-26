# Changes AI: AI-powered impact analysis for software package updates

[![Version](https://img.shields.io/badge/version-0.6.2-blue)](https://github.com/pzanna/changes-ai)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/pzanna/changes-ai)](https://github.com/pzanna/changes-ai/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/pzanna/changes-ai)](https://github.com/pzanna/changes-ai/issues)

<p align="center">
  <img src="https://raw.githubusercontent.com/pzanna/changes-ai/main/docs/owl.jpg" alt="Changes AI Logo" />
</p>

## News

- **[26/04/2026]** 🎉 First preview release (v0.6.2)!!

## Overview

Evaluates the impact of updating software packages to reduce the risk of
application upgrades.

Given either a **GitHub repository URL** or a **local project directory**,
**Changes AI**:

1. Discovers packages — from a dependency file in the repo
   (`requirements.txt`, `pyproject.toml`, or `uv.lock`) or by locating the
   `.venv` / `venv` directory inside a local project and reading its
   `site-packages/*.dist-info/METADATA` records.
2. Parses each package name and its pinned version (where one exists).
3. Fetches the **latest published version** of each package from
   [libraries.io](https://libraries.io).
4. Prints a **version mapping** as a table, JSON, or both, classifying every
   package as *up-to-date*, *outdated*, *unpinned* or *unknown*.
5. Optionally generates a **dependency chart** in ASCII and/or
   [Mermaid](https://mermaid.js.org/) format, with optional resolution of
   runtime transitive dependencies via libraries.io.
6. Optionally **scans for known CVEs** via the [OSV](https://osv.dev/) batch
   API, with severity-aware filtering and CI-friendly exit codes.
7. Optionally performs **AST-based usage analysis** — walks the project's
   source tree and maps each package to the symbols the code actually
   references, flagging dynamic imports, star imports and reflection patterns
   that can't be resolved statically.
8. Optionally runs **LLM-backed impact analysis** — for each vulnerable
   package, calls an OpenAI-compatible model to assess probable breakage,
   identify API changes that intersect the project's usage, and score
   confidence, giving you a prioritised upgrade recommendation rather than a
   raw CVE list.
9. Optionally runs the **LLM remediation planner** — synthesises the CVE data
   and impact reports into three ranked upgrade *paths* (minimum breakage,
   maximum coverage, balanced), each scored for exposure risk and breakage
   risk, with per-upgrade CVE annotations, unresolved CVE lists, and a
   dedicated callout for packages with no available fix.

---

## Background

The old vulnerability-management playbook — *disclose, triage, patch over a few
days* — assumed that finding and weaponising a vulnerability required serious
human expertise. That assumption is expiring.

In April 2026, Anthropic announced
[Project Glasswing](https://www.anthropic.com/glasswing), revealing that an
unreleased frontier model — Claude Mythos Preview — had autonomously
discovered thousands of zero-day vulnerabilities across *every major operating
system and web browser*, including a 27-year-old remote crash in OpenBSD that
had survived decades of human review. Similar capabilities are emerging from
other labs, and they will not stay contained to the labs that are deploying
them responsibly.

The window between disclosure and exploitation is collapsing from days to
minutes. On the defensive side, the slowest manual step is no longer *finding*
the vulnerability — OSV, NVD and libraries.io already surface that in seconds.
It's answering the follow-up question: **"given this CVE, in this project,
what's the lowest-risk change I can make?"** That question still eats hours of
senior-engineer time per incident, and it's the one Changes AI exists to
collapse.

---

## Requirements

- Python 3.10 or later
- A [libraries.io API key](https://libraries.io/api) (free tier, recommended to
  avoid rate limits)
- Optionally a GitHub personal access token (for private repos or to raise the
  GitHub API rate limit)

## Installation

Clone the repo and install it inside a virtual environment:

```bash
git clone https://github.com/pzanna/changes-ai.git
cd changes-ai
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

> **macOS note:** macOS ships with an older system Python and Homebrew manages its
> own Python as an externally-managed environment. Installing without a virtual
> environment will fail with an "externally managed" error. The steps above work
> on all platforms.

For local development:

```bash
pip install -e ".[dev]"
```

For PDF reports on MacOS:

```bash
brew install pango
```

## Usage

```bash
changes-ai [--url URL | --source PATH] [options]
changes-ai scan [--url URL | --source PATH] [options]
changes-ai graph [--url URL | --source PATH] [options]
changes-ai cves [--url URL | --source PATH] [options]
changes-ai usage --source PATH [options]
changes-ai plan [--url URL | --source PATH] [options]
changes-ai report [RUN_ID] [--format {json,table,md,html,pdf,sarif,dot}] [--report-template TEMPLATE_OR_CSS] [--output DIR_OR_FILE]
changes-ai cache list
changes-ai cache clear [--source SOURCE]
```

| Option | Description |
|---|---|
| `--version` | Print the Changes AI version and exit |
| `--url URL` | GitHub repository URL, e.g. `https://github.com/owner/repo`; cloned locally before analysis |
| `--source PATH` | Path to a local project directory; supported manifests are used when present, otherwise `.venv` or `venv` is auto-discovered |
| `--libraries-io-key KEY` | libraries.io API key (recommended) |
| `--github-token TOKEN` | GitHub personal access token (only used with `--url`) |
| `--repo-path PATH` | Directory where `--url` repositories are cloned (default: `CHANGES_AI_REPO_PATH` or `./repos`) |
| `--cache-db FILE` | SQLite cache database path (default: `~/.cache/changes-ai/cache.sqlite`) |
| `--offline` | Use only cached external API data; fail clearly if required data is missing or stale |
| `--refresh` | Bypass cached external API data and refresh from upstream services |
| `--output {table,json,both}` | Version-mapping output format (default: `table`) |
| `--format {json,table,md,html,pdf,sarif,dot}` | Report output format for `changes-ai report` and scan-generated summary reports (default: `CHANGES_AI_REPORT_FORMAT`; `json` for `report`, `md` for scan output) |
| `--report-template TEMPLATE_OR_CSS` | PDF report template name or path to a custom CSS file for `changes-ai report` and scan-generated summary reports (default: `CHANGES_AI_REPORT_TEMPLATE` or the built-in template) |
| `--chart` | Generate a dependency chart |
| `--chart-format {mermaid,ascii,dot,both}` | Chart format (default: `ascii`) |
| `--transitive` | Include transitive (sub-)dependencies in the Mermaid chart |
| `--chart-output FILE` | Write the selected chart format to `FILE` instead of stdout |
| `--report-output DIR_OR_FILE` | Write a summary report to a file or directory; directory outputs use `report_YYYYMMDD_HHMMSS.<format>`, and html reports create a folder containing `index.html` and `style.css` |
| `--all` | Run the full analysis suite: dependency chart, CVE scan, usage analysis, LLM impact analysis, and remediation planning |
| `--cve-scan` | Scan packages with concrete installed versions for known CVEs via the [OSV](https://osv.dev/) database; range-only or unpinned specs are skipped with a warning unless a local venv provides the installed version |
| `--severity-threshold LEVEL` | Only display CVEs at or above this level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` (default: `LOW`) |
| `--fail-on LEVEL` | Exit with code `2` if any CVE at or above LEVEL is found (use with `--cve-scan` for CI gating) |
| `--usage-analysis` | Analyse which symbols from each package the project's source actually uses (requires `--source`) |
| `--impact-analysis` | LLM-backed impact assessment for each vulnerable package (requires `--cve-scan` and `OPENAI_API_KEY`) |
| `--allow-commercial-usage-data` | Permit source-derived usage-analysis data to be sent to a known hosted commercial LLM endpoint |
| `--plan` | LLM remediation planner — ranked upgrade paths with exposure/breakage scores (requires `--impact-analysis`) |

## Examples

```bash
# Basic version mapping for a remote repo (table + JSON)
changes-ai --url https://github.com/owner/repo

# Equivalent subcommand form
changes-ai scan --url https://github.com/owner/repo

# Stage-focused subcommands reuse the same shared scan/cache path
changes-ai graph --source /path/to/project --transitive
changes-ai cves --source /path/to/project --severity-threshold HIGH
changes-ai usage --source /path/to/project
changes-ai plan --source /path/to/project --allow-commercial-usage-data
changes-ai report --format table
changes-ai report --format md --output ./reports
changes-ai report --format html --output ./reports
changes-ai report --format pdf --output ./reports
changes-ai report --format pdf --report-template corporate --output ./reports
changes-ai report --format sarif --output ./reports
changes-ai report --format dot --output changes-ai-graph.dot

# With a libraries.io key (avoids rate-limit warnings)
changes-ai --url https://github.com/owner/repo --libraries-io-key YOUR_KEY

# Show only the table, skip JSON
changes-ai --url https://github.com/owner/repo --output table

# Generate a dependency chart and save the Mermaid file
changes-ai --url https://github.com/owner/repo --chart --chart-output deps.mmd

# Export a DOT dependency graph
changes-ai --url https://github.com/owner/repo --chart --chart-format dot --chart-output deps.dot

# Include transitive dependencies in the chart
changes-ai --url https://github.com/owner/repo --chart --transitive

# Re-run using only cached libraries.io data
changes-ai scan --source /path/to/project --offline

# Refresh cached libraries.io data
changes-ai scan --source /path/to/project --refresh

# Inspect or clear cached API responses
changes-ai cache list
changes-ai cache clear --source libraries_io_package

# Scan a local project (auto-discovers .venv or venv inside the directory)
changes-ai --source /path/to/project

# Scan a local project from a dependency manifest even when no venv is present
changes-ai --source /path/to/project-with-requirements

# Scan a local project, table output only
changes-ai --source /path/to/project --output table

# Scan for CVEs and display HIGH+ severity only
changes-ai --source /path/to/project --cve-scan --severity-threshold HIGH

# Scan for CVEs and fail CI if any HIGH+ vulnerability is found
changes-ai --source /path/to/project --cve-scan --fail-on HIGH

# Scan a remote repo for CVEs with default (LOW+) display threshold
changes-ai --url https://github.com/owner/repo --cve-scan

# Analyse source usage for a local project
changes-ai --source /path/to/project --usage-analysis

# Full pipeline: CVE scan + usage analysis + LLM impact assessment
changes-ai --source /path/to/project \
    --cve-scan --usage-analysis --impact-analysis

# Impact analysis without usage (lower confidence, works with --url too)
changes-ai --url https://github.com/owner/repo \
    --cve-scan --impact-analysis

# Full pipeline: CVE scan + usage analysis + impact + remediation plan
changes-ai --source /path/to/project \
    --cve-scan --usage-analysis --impact-analysis --plan

# Full analysis suite using the shortcut
changes-ai --source /path/to/project --all

# Remediation plan without usage analysis (lower confidence)
changes-ai --source /path/to/project \
    --cve-scan --impact-analysis --plan
```

## Supported dependency file formats

| File | Format |
|---|---|
| `requirements.txt` | pip – supports `==`, `>=`, `~=`, etc. |
| `requirements/base.txt` | pip |
| `requirements/main.txt` | pip |
| `requirements/prod.txt` | pip |
| `pyproject.toml` | PEP 621 (`[project.dependencies]`) and Poetry (`[tool.poetry.dependencies]`) |
| `uv.lock` | uv lockfile (TOML) |

## Sample output

```text
Analysing source: /path/to/project (venv: /path/to/project/.venv)
Packages detected: 5
Fetching version information from libraries.io…

=== Version Mapping ===

Package           Installed Version    Requirement   Latest Version   Status
------------------------------------------------------------------------------
certifi           2024.2.2             >=2024.1.0    2024.2.2         ✓ up-to-date
idna              3.6                  >=3.4         3.7              ⚠ outdated
urllib3           2.2.1                >=2.0         2.2.1            ✓ up-to-date

=== Summary ===
Total packages : 5
Up-to-date     : 4
Outdated       : 1
Unpinned       : 0
Unknown        : 0
```

### CVE scan output (`--cve-scan`)

```text
Scanning for vulnerabilities via OSV…

=== CVE Scan (LOW+) ===

Package    Installed  CVE / ID                  Sev       Fixed In
-------------------------------------------------------------------
requests   2.28.0     GHSA-j8r2-6x86-q33q       ⚠ HIGH     2.31.0
urllib3    1.26.5     GHSA-v845-jxx5-vc9f       ⚠ HIGH     1.26.11, 2.0.7
```

### Usage analysis output (`--usage-analysis`)

```
=== Usage Analysis ===

Package     Symbols used
-----------------------------------
requests    get, post, Session
flask       Flask, render_template

--- Unresolved / flagged ---
  star_import       utils.py:3
  dynamic_import    plugins.py:14
```

### Impact analysis output (`--cve-scan --usage-analysis --impact-analysis`)

```text
=== Impact Analysis ===

Package    Upgrade                Delta   Breakage           Confidence
-----------------------------------------------------------------------
requests   2.28.0 → 2.31.0       minor   ○ LOW (0.05)       ✓ HIGH
  Used: get, post, Session
  Minor release fixing GHSA-j8r2-6x86-q33q; no public API changes documented.

urllib3    1.26.5 → 1.26.11      patch   ○ LOW (0.02)       ✓ HIGH
  Used: HTTPSConnectionPool
  Patch release; no breaking API changes expected.
```

### Remediation plan output (`--cve-scan --usage-analysis --impact-analysis --plan`)

```text
=== Remediation Plan ===

3 path(s) generated: minimum breakage 2/4 · balanced 3/4 · maximum coverage 4/4.

[Minimum Breakage]  Exposure: 0.62  Breakage: 0.10  Confidence: ✓ HIGH
  ↑  requests  2.28.0 → 2.31.0  (fixes GHSA-j8r2-6x86-q33q)
  Resolves:   GHSA-j8r2-6x86-q33q
  Open:       GHSA-v845-jxx5-vc9f

[Maximum Coverage]  Exposure: 0.00  Breakage: 0.45  Confidence: ~ MEDIUM
  ↑  requests  2.28.0 → 2.32.3  (fixes GHSA-j8r2-6x86-q33q)
  ↑  urllib3   1.26.5 → 2.2.3   (fixes GHSA-v845-jxx5-vc9f)
  Resolves:   GHSA-j8r2-6x86-q33q, GHSA-v845-jxx5-vc9f

[Balanced]  Exposure: 0.20  Breakage: 0.22  Confidence: ✓ HIGH
  ↑  requests  2.28.0 → 2.31.0  (fixes GHSA-j8r2-6x86-q33q)
  ↑  urllib3   1.26.5 → 1.26.18 (fixes GHSA-v845-jxx5-vc9f)
  Resolves:   GHSA-j8r2-6x86-q33q, GHSA-v845-jxx5-vc9f
  This path upgrades both packages within their current major versions,
  avoiding the urllib3 1.x → 2.x API break while closing all known CVEs.
```

**Exit codes** (when `--fail-on` is set):

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities at or above the threshold |
| `1` | Tool error |
| `2` | One or more vulnerabilities found at or above the `--fail-on` threshold |

## Configuration via `.env` file

Create a `.env` file in the project directory to store API keys so you never
have to pass them on the command line:

```dotenv
# .env
LIBRARIES_IO_API_KEY=your_libraries_io_api_key
GITHUB_TOKEN=your_github_token          # optional
OPENAI_API_KEY=your_openai_api_key      # required for --impact-analysis
OPENAI_MODEL=gpt-4o-mini               # default model
OPENAI_API_BASE=https://api.openai.com/v1  # override for local/alternative endpoints
CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA=0   # set to 1 to allow usage data to hosted LLMs
CHANGES_AI_SOURCE_PATH=/path/to/project     # optional default for --source
CHANGES_AI_REPO_PATH=/path/to/repos         # clone root for --url repos
CHANGES_AI_CACHE_DB=/path/to/cache.sqlite  # optional cache database override
CHANGES_AI_REPORT_PATH=/path/to/reports    # report folder; writes report_YYYYMMDD_HHMMSS.<format>
CHANGES_AI_REPORT_FORMAT=md                # json, table, md, html, pdf, sarif, or dot
CHANGES_AI_REPORT_TEMPLATE=corporate       # built-in template name or path to custom CSS for PDF reports
CHANGES_AI_CHART_OUTPUT=changes-ai-deps.mmd    # optional default chart file
```

Changes AI automatically loads this file on startup.
Key priority: CLI flag → environment variable → `.env` file.

> **Note**: `.env` is already listed in `.gitignore` — your keys will not be
> accidentally committed.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `LIBRARIES_IO_API_KEY` | Recommended | Avoids rate limits on version/dependency lookups |
| `GITHUB_TOKEN` | Optional | For private repos or higher GitHub API rate limits |
| `OPENAI_API_KEY` | For `--impact-analysis` / `--plan` | API key for the LLM endpoint |
| `OPENAI_MODEL` | Optional | Model name (default: `gpt-4o-mini`) |
| `OPENAI_API_BASE` | Optional | Base URL for the completions endpoint (default: `https://api.openai.com/v1`); set to a local vLLM/Ollama URL for self-hosted models |
| `CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA` | Optional | Set to `1`, `true`, or `yes` to allow source-derived usage-analysis data to be sent to known hosted commercial LLM endpoints |
| `CHANGES_AI_SOURCE_PATH` | Optional | Default local project path when neither `--source` nor `--url` is passed |
| `CHANGES_AI_REPO_PATH` | Optional | Directory where repositories passed with `--url` are cloned |
| `CHANGES_AI_CACHE_DB` | Optional | Override the SQLite cache database path |
| `CHANGES_AI_REPORT_PATH` | Optional | Report output directory; report files are written as `report_YYYYMMDD_HHMMSS.<format>` |
| `CHANGES_AI_REPORT_FORMAT` | Optional | Default report format for generated reports: `json`, `table`, `md`, `html`, `pdf`, `sarif`, or `dot` |
| `CHANGES_AI_REPORT_TEMPLATE` | Optional | Default PDF report template name or path to a custom CSS file |
| `CHANGES_AI_CHART_OUTPUT` | Optional | Default dependency chart output path |

When `--usage-analysis` is enabled, Changes AI refuses to send source-derived
symbol data to known hosted commercial LLM endpoints unless you opt in with
`--allow-commercial-usage-data` or `CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA=1`.
Self-hosted/local endpoints such as `localhost` do not require this opt-in.

## Auth Model

- `--libraries-io-key` overrides `LIBRARIES_IO_API_KEY`.
- `--github-token` overrides `GITHUB_TOKEN`.
- `.env` values are loaded on startup and act like normal environment variables.
- Remote GitHub scans use `GITHUB_TOKEN` for `git clone` and GitHub release-note evidence; local source scans do not need it.

## Privacy Model

Outbound requests vary by feature:

- Version and dependency metadata: libraries.io.
- CVE metadata: OSV.
- Package metadata and changelog hints: PyPI.
- Release-note evidence for public repositories: GitHub APIs.
- LLM impact and remediation analysis: the configured OpenAI-compatible endpoint.

Scan-generated executive summaries use a local deterministic fallback by
default. When `--impact-analysis` is enabled and `OPENAI_API_KEY` is available,
Changes AI may also ask the configured LLM endpoint to write the executive
summary narrative from already-collected report facts.

Source-derived usage data is only sent to the LLM endpoint when you enable
`--usage-analysis` together with `--impact-analysis` or `--plan`. Hosted
commercial endpoints require explicit opt-in. For stricter handling, either:

- skip `--usage-analysis` when using hosted endpoints,
- point `OPENAI_API_BASE` at a self-hosted/local endpoint, or
- run with `--offline` after the required cache is populated.

## Offline Mode

- `--offline` allows report regeneration and cached analysis without new outbound requests.
- `--refresh` forces fresh upstream fetches and cannot be combined with `--offline`.
- If required cached data is missing or stale, offline mode fails explicitly instead of silently degrading.

## Roadmap

The current release (**v0.6.2**) covers package discovery, version mapping,
dependency charts, CVE scanning, AST-based usage analysis, LLM-backed
impact analysis, the LLM remediation planner, SQLite-backed libraries.io, OSV,
PyPI, and LLM response caching, offline/refresh controls, stage-focused `scan`,
`graph`, `cves`, `usage`, `plan`, `report`, and `cache` subcommands, persisted
run artifacts, Markdown report regeneration, SARIF output, DOT graph export,
currency and deprecation signals, cited changelog or release-note evidence in
impact reports, and local cloning for GitHub repository URLs.
