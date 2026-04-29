# Changelog

All notable changes to Changes AI will be documented in this file.

This project follows a pragmatic preview-release format. Versions are currently
published as preview milestones until the public API and CLI behavior stabilize.

## [0.7.0] - 01-05-2026

### Added

- Add links to the individual CVEs in the reports.
- Added automated remediation support via the `remediate` subcommand, which generates and applies upgrade recommendations based on LLM analysis.
- Added a GitHub Actions workflow template for running Changes AI scans on pull requests and commits, with example configuration and usage instructions.

### Fixed

- Updated installation notes for pdf/graph packages to include Linux in the README

## [0.6.3] - 27-04-2026

### Added

- Added CSS styling the evidence list in HTML reports to improve readability and visual distinction of different evidence types.
- Added GraphViz to produce more polished and informative dependency graph visualizations in HTML and PDF reports, with improved layout and styling.

### Fixed

- Tool-only `pyproject.toml` files no longer block manifest discovery; scans now fall through to `environment.yml` when no supported project dependencies are declared.

---

## [0.6.2] - 26-04-2026

### Added

- Public preview release.
- Updated documentation and examples to reflect the latest behavior and CLI flags.
- Added a code of conduct and security policy for responsible contribution and
  vulnerability reporting.
- Added a contributing guide with development setup instructions, contribution
  guidelines, and commit message recommendations.
- Added HTML report format which allows customised style and layout via CSS templates.
- Added Executive Summary section to reports for a high-level overview of key findings and recommendations.

### Fixed

- Standardised public repository references to `pzanna/changes-ai` and CLI examples
  to the installed `changes-ai` command.
- Scan-generated executive summaries no longer call the configured LLM endpoint
  unless LLM impact analysis was explicitly enabled for the run.
- CVE scans now warn when a manifest dependency cannot be resolved to a concrete
  installed version for OSV scanning.

---

## [0.6.1] - 2026-04-25

### Added

- Dependency discovery from `requirements.txt`, `requirements/base.txt`,
  `requirements/main.txt`, `requirements/prod.txt`, `pyproject.toml`, `uv.lock`,
  and local Python virtual environments.
- Version mapping with table and JSON output.
- Dependency graph export in ASCII, Mermaid, and DOT formats.
- CVE scanning via OSV with severity filtering and CI-friendly `--fail-on`
  exit codes.
- AST-based usage analysis for Python source trees.
- LLM-backed impact analysis using an OpenAI-compatible endpoint.
- LLM-backed remediation planning with ranked upgrade paths.
- SQLite-backed API and run-artifact cache with offline and refresh modes.
- Cached report rendering in JSON, Markdown, HTML bundles, SARIF, table, and
  DOT formats.
- Styled PDF report rendering via WeasyPrint with built-in CSS templates.
- PDF report template selection via `--report-template` and
  `CHANGES_AI_REPORT_TEMPLATE`.
- Privacy guard requiring explicit opt-in before sending source-derived usage
  data to known hosted commercial LLM endpoints.

### Changed

- Top-level scan runs now accept `--format` for generated summary reports, not
  just the `report` subcommand.
- HTML report output now writes a `report_YYYYMMDD_HHMMSS.html` directory
  containing `index.html` and `style.css`.
- Corporate PDF reports now include the application version in the footer and
  force section-level page breaks, including a dedicated break before the
  vulnerabilities table.

### Fixed

- Report CSS template lookup now resolves correctly from `templates/reports`
  and uses the built-in default template reliably.
- PDF report generation now respects `CHANGES_AI_REPORT_TEMPLATE` and
  `--report-template` across both cached report rendering and scan-generated
  reports.

### Known Limitations

- The preview is focused on Python/PyPI projects.
- Static usage analysis can miss dynamic behavior and intentionally flags
  dynamic imports, star imports, entry points, and reflection.
- LLM-backed analysis quality depends on available release evidence, usage
  analysis completeness, and the configured model.
- Public preview behavior may change before a stable 1.0 release.
