import json
import subprocess
import sys

import pytest

import src
from src.cache import SQLiteCache
from src.changes_ai import (
    DependencyParser,
    _build_cve_scan_packages,
    _executive_summary_api_key,
    _format_skipped_cve_packages,
    parse_github_url,
)
from src.reporting import render_markdown_report
from src.render_report import (
    _resolve_css_path,
    render_report_html,
    render_report_html_bundle,
)


def _check_weasyprint() -> bool:
    """Return True if WeasyPrint and its system dependencies are available."""
    try:
        from weasyprint import HTML  # noqa: PLC0415

        HTML(string="<p>test</p>").write_pdf()
        return True
    except (ImportError, OSError, RuntimeError):
        return False


@pytest.fixture(scope="module")
def weasyprint_available():
    """Skip the test if WeasyPrint system dependencies are not available."""
    if not _check_weasyprint():
        pytest.skip("WeasyPrint system dependencies not available")


def test_public_import_surface_exposes_version():
    assert src.__version__
    assert src.parse_github_url("https://github.com/pzanna/changes-ai") == (
        "pzanna",
        "changes-ai",
    )


def test_dependency_parser_handles_pyproject_dependencies():
    content = """
[project]
dependencies = [
    "requests>=2.28.0",
    "python-dotenv==1.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"""

    assert DependencyParser.parse(content, "pyproject") == {
        "requests": ">=2.28.0",
        "python-dotenv": "==1.0.0",
        "pytest": ">=7.0.0",
    }


def test_cli_version_smoke():
    result = subprocess.run(
        [sys.executable, "-m", "src.changes_ai", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"changes-ai {src.__version__}"


def test_executive_summary_llm_key_requires_impact_analysis(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    assert _executive_summary_api_key(False) is None
    assert _executive_summary_api_key(True) == "test-key"


def test_cve_scan_packages_warns_for_non_concrete_specs_without_venv():
    scan_packages, skipped = _build_cve_scan_packages(
        {
            "requests": ">=2.28.0",
            "urllib3": "==1.26.5",
            "flask": None,
        },
        venv_pkgs=None,
    )

    assert scan_packages == {"urllib3": "1.26.5"}
    assert skipped == [("requests", ">=2.28.0"), ("flask", None)]
    warning = _format_skipped_cve_packages(skipped)
    assert "CVE scan skipped 2 package(s)" in warning
    assert "requests (>=2.28.0)" in warning
    assert "flask (unpinned)" in warning


def test_cve_scan_packages_uses_venv_versions_for_range_specs():
    scan_packages, skipped = _build_cve_scan_packages(
        {"requests": ">=2.28.0"},
        venv_pkgs={"requests": "2.28.1", "certifi": "2024.2.2"},
    )

    assert scan_packages == {"requests": "2.28.1", "certifi": "2024.2.2"}
    assert skipped == []


def test_report_css_template_path_resolves():
    css_path = _resolve_css_path("corporate")

    assert css_path.name == "corporate.css"
    assert css_path.is_file()


def test_report_html_footer_includes_version():
    html = render_report_html(
        """# Changes AI Remediation Report

## Executive Summary

- Run ID: 1
- Target: demo
- Packages analysed: 1
- Vulnerabilities found: 0
- Remediation paths: 0
"""
    )

    assert f"Changes AI - v{src.__version__}" in html


def test_report_html_bundle_contains_index_and_style():
    bundle = render_report_html_bundle(
        """# Changes AI Remediation Report

## Executive Summary

- Run ID: 1
- Target: demo
- Packages analysed: 1
- Vulnerabilities found: 0
- Remediation paths: 0
"""
    )

    assert set(bundle) == {"index.html", "style.css"}
    assert 'href="style.css"' in bundle["index.html"]
    assert bundle["style.css"].strip()


def test_markdown_report_uses_executive_summary_narrative():
    markdown = render_markdown_report(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {"edges": []},
            "vulnerabilities": [],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [],
            "remediation_paths": [],
            "executive_summary": {
                "narrative": "This run found a limited amount of upgrade risk and no active remediation blockers."
            },
        }
    )

    assert "This run found a limited amount of upgrade risk" in markdown
    assert "- Run ID:" not in markdown


def test_report_html_renders_executive_summary_narrative():
    html = render_report_html(
        """# Changes AI Remediation Report

## Executive Summary

<!-- executive-summary-meta: {\"Packages analysed\": \"1\", \"Remediation paths\": \"0\", \"Run ID\": \"1\", \"Target\": \"demo\", \"Vulnerabilities found\": \"0\"} -->

This run found a limited amount of upgrade risk and no active remediation blockers.

## Vulnerabilities by Severity

No cached vulnerabilities for this run.
"""
    )

    assert "This run found a limited amount of upgrade risk" in html


def test_main_command_accepts_report_format_option():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "--source",
            ".",
            "--all",
            "--format",
            "pdf",
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--format {json,table,md,html,pdf,sarif,dot}" in result.stdout


def test_main_command_accepts_report_template_option():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "--source",
            ".",
            "--all",
            "--report-template",
            "corporate",
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--report-template REPORT_TEMPLATE" in result.stdout


def test_report_command_writes_timestamped_file(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.sqlite"
    output_dir = tmp_path / "reports"

    cache = SQLiteCache(cache_path)
    try:
        run_id = cache.start_run(locator="smoke-test")
        cache.store_packages(
            run_id,
            [
                {
                    "name": "requests",
                    "installed": "2.33.1",
                    "requirement": ">=2.28.0",
                    "latest": "2.33.1",
                    "status": "up-to-date",
                }
            ],
        )
        cache.finish_run(run_id)
    finally:
        cache.close()

    monkeypatch.setenv("CHANGES_AI_REPORT_PATH", str(output_dir))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "report",
            str(run_id),
            "--format",
            "json",
            "--cache-db",
            str(cache_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    reports = list(output_dir.glob("report_*.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text(encoding="utf-8"))["run"]["id"] == run_id


def test_report_command_uses_default_format_from_env(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.sqlite"
    output_dir = tmp_path / "reports"

    cache = SQLiteCache(cache_path)
    try:
        run_id = cache.start_run(locator="smoke-test")
        cache.store_packages(
            run_id,
            [
                {
                    "name": "requests",
                    "installed": "2.33.1",
                    "requirement": ">=2.28.0",
                    "latest": "2.33.1",
                    "status": "up-to-date",
                }
            ],
        )
        cache.finish_run(run_id)
    finally:
        cache.close()

    monkeypatch.setenv("CHANGES_AI_REPORT_PATH", str(output_dir))
    monkeypatch.setenv("CHANGES_AI_REPORT_FORMAT", "sarif")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "report",
            str(run_id),
            "--cache-db",
            str(cache_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    reports = list(output_dir.glob("report_*.sarif"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_report_command_writes_pdf_report(tmp_path, monkeypatch, weasyprint_available):
    cache_path = tmp_path / "cache.sqlite"
    output_dir = tmp_path / "reports"

    cache = SQLiteCache(cache_path)
    try:
        run_id = cache.start_run(locator="smoke-test")
        cache.store_packages(
            run_id,
            [
                {
                    "name": "requests",
                    "installed": "2.33.1",
                    "requirement": ">=2.28.0",
                    "latest": "2.33.1",
                    "status": "up-to-date",
                }
            ],
        )
        cache.finish_run(run_id)
    finally:
        cache.close()

    monkeypatch.setenv("CHANGES_AI_REPORT_PATH", str(output_dir))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "report",
            str(run_id),
            "--format",
            "pdf",
            "--cache-db",
            str(cache_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    reports = list(output_dir.glob("report_*.pdf"))
    assert len(reports) == 1
    pdf_bytes = reports[0].read_bytes()
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 0


def test_report_command_writes_html_report_bundle(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.sqlite"
    output_dir = tmp_path / "reports"

    cache = SQLiteCache(cache_path)
    try:
        run_id = cache.start_run(locator="smoke-test")
        cache.store_packages(
            run_id,
            [
                {
                    "name": "requests",
                    "installed": "2.33.1",
                    "requirement": ">=2.28.0",
                    "latest": "2.33.1",
                    "status": "up-to-date",
                }
            ],
        )
        cache.finish_run(run_id)
    finally:
        cache.close()

    monkeypatch.setenv("CHANGES_AI_REPORT_PATH", str(output_dir))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "report",
            str(run_id),
            "--format",
            "html",
            "--cache-db",
            str(cache_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    reports = list(output_dir.glob("report_*.html"))
    assert len(reports) == 1
    assert reports[0].is_dir()
    assert (reports[0] / "index.html").is_file()
    assert (reports[0] / "style.css").is_file()


def test_report_command_uses_template_from_env_for_pdf(
    tmp_path, monkeypatch, weasyprint_available
):
    cache_path = tmp_path / "cache.sqlite"
    output_dir = tmp_path / "reports"

    cache = SQLiteCache(cache_path)
    try:
        run_id = cache.start_run(locator="smoke-test")
        cache.store_packages(
            run_id,
            [
                {
                    "name": "requests",
                    "installed": "2.33.1",
                    "requirement": ">=2.28.0",
                    "latest": "2.33.1",
                    "status": "up-to-date",
                }
            ],
        )
        cache.finish_run(run_id)
    finally:
        cache.close()

    monkeypatch.setenv("CHANGES_AI_REPORT_PATH", str(output_dir))
    monkeypatch.setenv("CHANGES_AI_REPORT_TEMPLATE", "corporate")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.changes_ai",
            "report",
            str(run_id),
            "--format",
            "pdf",
            "--cache-db",
            str(cache_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    reports = list(output_dir.glob("report_*.pdf"))
    assert len(reports) == 1
