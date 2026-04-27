import json
import subprocess
import sys

import pytest

import src
import src.reporting as reporting_module
from src.cache import SQLiteCache
from src.changes_ai import (
    DependencyParser,
    _build_cve_scan_packages,
    _executive_summary_api_key,
    _format_skipped_cve_packages,
    parse_github_url,
)
from src.graph import render_dot_graph, render_svg_graph
from src.reporting import (
    render_html_report_bundle as render_cached_html_report_bundle,
    render_markdown_report,
)
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


def test_dependency_parser_ignores_tool_only_pyproject_sections():
    content = """
[tool.isort]
extra_standard_library = [
    "numpy",
    "torch",
]
"""

    assert DependencyParser.parse(content, "pyproject") == {}


def test_dependency_parser_handles_conda_environment_dependencies():
    content = """
channels:
  - conda-forge
dependencies:
  - python=3.11
  - pytorch-cuda=12.1
  - pip
  - pip:
      - gymnasium==1.2.0
      - tensorboard>=2.16
"""

    assert DependencyParser.parse(content, "conda") == {
        "python": "==3.11",
        "pytorch-cuda": "==12.1",
        "pip": None,
        "gymnasium": "==1.2.0",
        "tensorboard": ">=2.16",
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


def test_markdown_report_embeds_dependency_graph_svg_when_provided():
    markdown = render_markdown_report(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {"edges": [{"parent": "demo", "child": "requests"}]},
            "vulnerabilities": [],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [],
            "remediation_paths": [],
            "executive_summary": {},
        },
        dependency_graph_svg="<svg><rect /></svg>",
    )

    assert '<div class="dependency-graph-svg">' in markdown
    assert "<svg><rect /></svg>" in markdown
    assert "Cached edges:" not in markdown


def test_render_dot_graph_uses_top_down_compact_layout():
    dot_graph = render_dot_graph(
        [{"parent": "demo", "child": "requests"}],
        graph_name="demo",
    )

    assert 'rankdir="TB";' in dot_graph
    assert 'fontname="Helvetica,Arial,sans-serif";' in dot_graph
    assert 'nodesep="0.25";' in dot_graph
    assert 'ranksep="0.35";' in dot_graph


def test_render_dot_graph_wraps_large_root_fanout_into_rows():
    edges = [
        {"parent": "demo", "child": f"dep{i}"}
        for i in range(10)
    ]

    dot_graph = render_dot_graph(edges, graph_name="demo")

    assert "__changes_ai_wrap_0_0" in dot_graph
    assert "__changes_ai_wrap_0_1" in dot_graph
    assert '{ rank=same; "__changes_ai_wrap_0_0"' in dot_graph
    assert '"__changes_ai_wrap_0_0" -> "__changes_ai_wrap_0_1" [style=invis, weight=100];' in dot_graph
    assert '"demo" -> "dep0" [constraint=false];' in dot_graph


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


def test_cached_html_report_bundle_embeds_graphviz_svg(monkeypatch):
    monkeypatch.setattr(
        reporting_module,
        "render_svg_graph",
        lambda edges, graph_name="changes_ai": "<svg><text>graph</text></svg>",
    )

    bundle = render_cached_html_report_bundle(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {"edges": [{"parent": "demo", "child": "requests"}]},
            "vulnerabilities": [],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [],
            "remediation_paths": [],
            "executive_summary": {},
        }
    )

    assert "<svg><text>graph</text></svg>" in bundle["index.html"]
    assert "Cached edges:" not in bundle["index.html"]


def test_report_html_wraps_impact_analysis_list():
    html = render_report_html(
        """# Changes AI Remediation Report

## Executive Summary

- Run ID: 1
- Target: demo
- Packages analysed: 1
- Vulnerabilities found: 1
- Remediation paths: 0

## Impact Summary

| Package | Upgrade | Breakage | Confidence |
|---|---|---|---|
| requests | 2.31.0 -> 2.32.0 | low (0.2) | medium |

- requests 2.31.0 -> 2.32.0: Release notes mention a transport-layer change.
  Citation: changelog - requests 2.32.0 (https://example.com/requests-2.32.0)

## Dependency Graph

No cached dependency graph edges.
"""
    )

    assert '<div class="impact-analysis"><ul>' in html


def test_render_svg_graph_strips_graphviz_preamble(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout='<?xml version="1.0"?>\n<!DOCTYPE svg>\n<svg><text>graph</text></svg>\n',
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    svg = render_svg_graph([{"parent": "demo", "child": "requests"}], graph_name="demo")

    assert svg == "<svg><text>graph</text></svg>"


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
    reports = [path for path in output_dir.glob("report_*") if path.is_dir()]
    assert len(reports) == 1
    assert reports[0].is_dir()
    assert reports[0].suffix == ""
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
