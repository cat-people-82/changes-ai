# Using Changes AI with GitHub Actions

Changes AI can be integrated into a GitHub Actions workflow to automatically
scan a repository for dependency vulnerabilities on every push or pull request.

## Overview

The typical workflow:

1. Check out the repository
2. Set up Python and install the project's own dependencies
3. Install Changes AI from PyPI (or the GitHub repository)
4. Run `changes-ai scan` against the source tree
5. Upload the generated report as a workflow artifact

## Permissions

The workflow job needs the following permissions:

```yaml
permissions:
  contents: read
  security-events: write   # only required if uploading SARIF to GitHub Security
```

## Installing Changes AI

Install Changes AI directly from the GitHub repository to always use the
latest version from the `main` branch:

```yaml
- name: Install Changes AI
  run: |
    python -m pip install --upgrade pip
    python -m pip install "git+https://github.com/pzanna/changes-ai.git@main"
```

Or pin to a specific release tag for reproducible builds:

```yaml
python -m pip install "git+https://github.com/pzanna/changes-ai.git@v0.7.0"
```

## Running the scan

A minimal scan with CVE checking and usage analysis:

```yaml
- name: Run Changes AI scan
  env:
    LIBRARIES_IO_API_KEY: ${{ secrets.LIBRARIES_IO_API_KEY }}
  run: |
    mkdir -p changes-ai-reports
    changes-ai scan \
      --source . \
      --cve-scan \
      --usage-analysis \
      --severity-threshold LOW \
      --report-output changes-ai-reports \
      --format md \
      --cache-db changes-ai-cache.sqlite
```

### Common flags

| Flag | Purpose |
|------|---------|
| `--source .` | Scan the checked-out repository root |
| `--cve-scan` | Query OSV for known CVEs in detected dependencies |
| `--usage-analysis` | Collect symbol-level usage to improve impact confidence |
| `--severity-threshold LEVEL` | Filter output to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN` |
| `--fail-on LEVEL` | Exit with code `2` if any CVE at or above LEVEL is found — use this to fail the CI job |
| `--report-output DIR` | Write the report to a directory (filename is auto-generated) |
| `--format {md,html,pdf,sarif,json}` | Report format; use `sarif` to upload results to GitHub Security |
| `--cache-db FILE` | SQLite cache path; persist between runs with `actions/cache` to reduce API calls |
| `--offline` | Use only cached data; useful for runs that should not make external API calls |

## Uploading the report as an artifact

```yaml
- name: Upload Changes AI report
  uses: actions/upload-artifact@v4
  with:
    name: changes-ai-report
    path: changes-ai-reports/
    if-no-files-found: warn
```

## Failing the build on vulnerabilities

Add `--fail-on HIGH` (or any other severity) to exit with code `2` when
matching CVEs are found, which marks the workflow job as failed:

```yaml
changes-ai scan \
  --source . \
  --cve-scan \
  --fail-on HIGH \
  --severity-threshold HIGH
```

## API keys and secrets

Store sensitive values as [GitHub Actions secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)
and pass them as environment variables:

| Secret | Environment variable | Purpose |
|--------|---------------------|---------|
| `LIBRARIES_IO_API_KEY` | `LIBRARIES_IO_API_KEY` | Currency and version data (recommended) |
| `OPENAI_API_KEY` | `OPENAI_API_KEY` | Required for `--impact-analysis` and `--plan` |
| `GITHUB_TOKEN` | `GITHUB_TOKEN` | Only needed when scanning a remote `--url` repository |

```yaml
env:
  LIBRARIES_IO_API_KEY: ${{ secrets.LIBRARIES_IO_API_KEY }}
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Caching between runs

Persist the SQLite cache across workflow runs to avoid redundant API calls:

```yaml
- name: Restore Changes AI cache
  uses: actions/cache@v4
  with:
    path: changes-ai-cache.sqlite
    key: changes-ai-cache-${{ runner.os }}
```

Place this step before the scan step and pass the same path via `--cache-db`.

An example workflow file can be found in the [GitHub repository](https://github.com/pzanna/changes-ai/blob/main/docs/github-actions-example.yml).
