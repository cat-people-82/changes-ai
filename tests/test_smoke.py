import json
import subprocess
import sys
from pathlib import Path

import pytest

import src
import src.apply as apply_module
import src.changes_ai as changes_ai_module
import src.graph as graph_module
import src.remediation_editor as remediation_editor_module
import src.reporting as reporting_module
import src.vulnerability as vulnerability_module
from src.cache import SQLiteCache
from src.changes_ai import (
    DependencyParser,
    _build_graph_packages,
    _build_cve_scan_packages,
    _executive_summary_api_key,
    _format_skipped_cve_packages,
    parse_github_url,
)
from src.ecosystem import (
    ApplyOutcome,
    CurrencyRecord,
    GraphEdge,
    ManifestInfo,
    NpmAdapter,
    Package,
    PythonAdapter,
    UsageRecord,
    UsageResult,
    detect_adapter,
)
from src.ecosystem.js_usage import analyse_project as analyse_js_project
from src.ecosystem.npm_adapter import NpmRegistryClient
from src.graph import render_dot_graph, render_svg_graph
from src.impact import ImpactReport
from src.remediation import RemediationPath, RemediationUpgrade, _build_planning_context, _compute_exposure_score
from src.reporting import (
    render_html_report_bundle as render_cached_html_report_bundle,
    render_markdown_report,
)
from src.render_report import (
    _resolve_css_path,
    render_report_html,
    render_report_html_bundle,
)
from src.vulnerability import OSVClient, VulnerabilityRecord, scan_vulnerabilities


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


def test_dependency_parser_handles_conda_environment_without_pyyaml(monkeypatch):
    content = """
dependencies:
  - python=3.11
  - pip:
      - gymnasium==1.2.0
"""

    monkeypatch.setattr(changes_ai_module, "_load_yaml_module", lambda: None)

    assert DependencyParser.parse(content, "conda") == {
        "python": "==3.11",
        "gymnasium": "==1.2.0",
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


def test_ecosystem_protocol_satisfied_by_python_adapter():
    adapter = PythonAdapter()

    assert adapter.name == "python"
    assert adapter.osv_ecosystem == "PyPI"
    for attr in (
        "manifest_candidates",
        "find_manifest",
        "parse_manifest",
        "discover_installed",
        "fetch_currency",
        "build_graph",
        "analyse_usage",
        "write_manifest",
        "regenerate_lockfile",
        "install",
        "dry_run_validate",
    ):
        assert callable(getattr(adapter, attr))

    package = Package("requests", "2.32.0", ">=2.0")
    edge = GraphEdge("project", "requests")
    currency = CurrencyRecord("requests", "2.32.0", "2.32.5", None, None, False)
    usage_record = UsageRecord("requests", "get", "app.py", 12)
    usage_result = UsageResult(records=[usage_record], unresolved=[])
    manifest = ManifestInfo(tmp_path := Path("/tmp/demo"), "pyproject", False, None, None)
    outcome = ApplyOutcome(True, "ok")

    assert package.name == "requests"
    assert package.installed_version == "2.32.0"
    assert package.declared_constraint == ">=2.0"
    assert edge.parent == "project"
    assert edge.child == "requests"
    assert currency.deprecated is False
    assert currency.signals == []
    assert usage_result.packages_used() == {"requests"}
    assert manifest.path == tmp_path
    assert outcome.files_modified == []


def test_detect_adapter_finds_python_for_pyproject_only(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

    adapter = detect_adapter(tmp_path)

    assert adapter is not None
    assert adapter.name == "python"


def test_detect_adapter_returns_none_for_empty_directory(tmp_path):
    assert detect_adapter(tmp_path) is None


def test_detect_adapter_chooses_npm_for_package_json_only(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo","dependencies":{"left-pad":"^1.0.0"}}', encoding="utf-8")

    adapter = detect_adapter(tmp_path)

    assert adapter is not None
    assert adapter.name == "npm"


def test_detect_adapter_polyglot_warns_and_prefers_python(tmp_path, capsys):
    (tmp_path / "package.json").write_text('{"name":"demo","dependencies":{"left-pad":"^1.0.0"}}', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['requests>=2.0']\n", encoding="utf-8")

    adapter = detect_adapter(tmp_path)
    captured = capsys.readouterr()

    assert adapter is not None
    assert adapter.name == "python"
    assert "multiple ecosystems detected" in captured.err
    assert "python, npm" in captured.err


class _FakeJSONResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _RecordingOSVSession:
    def __init__(self, post_payload=None, get_payload=None):
        self.headers = {}
        self.post_payload = post_payload or {"results": [{}]}
        self.get_payload = get_payload or {}
        self.recorded_posts: list[dict] = []
        self.recorded_gets: list[str] = []

    def post(self, url, json=None, timeout=None):
        self.recorded_posts.append({"url": url, "json": json, "timeout": timeout})
        return _FakeJSONResponse(200, self.post_payload)

    def get(self, url, timeout=None):
        self.recorded_gets.append(url)
        return _FakeJSONResponse(200, self.get_payload)


def test_osv_client_uses_ecosystem_parameter():
    client = OSVClient()
    session = _RecordingOSVSession()
    client.session = session

    client.query_batch([("left-pad", "1.0.0")], ecosystem="npm")

    assert session.recorded_posts[0]["json"] == {
        "queries": [
            {
                "package": {"name": "left-pad", "ecosystem": "npm"},
                "version": "1.0.0",
            }
        ]
    }


def test_osv_client_default_ecosystem_pypi_unchanged():
    client = OSVClient()
    session = _RecordingOSVSession()
    client.session = session

    client.query_batch([("requests", "2.31.0")])

    assert session.recorded_posts[0]["json"] == {
        "queries": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "version": "2.31.0",
            }
        ]
    }


def test_osv_response_filtering_respects_ecosystem(monkeypatch):
    session = _RecordingOSVSession(
        post_payload={"results": [{"vulns": [{"id": "OSV-1"}]}]},
        get_payload={
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "left-pad"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
                },
                {
                    "package": {"ecosystem": "npm", "name": "left-pad"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
                },
            ],
            "database_specific": {"severity": "HIGH"},
        },
    )
    monkeypatch.setattr(vulnerability_module.requests, "Session", lambda: session)

    records = scan_vulnerabilities({"left-pad": "1.0.0"}, ecosystem="npm")

    assert len(records) == 1
    assert records[0].package == "left-pad"
    assert records[0].fixed_versions == ["1.0.1"]
    assert records[0].affected_ranges == [">= 0, < 1.0.1"]


def test_npm_parse_package_json_collects_all_dep_sections():
    content = Path("tests/fixtures/npm/package-all-deps.json").read_text(encoding="utf-8")

    parsed = NpmAdapter().parse_manifest(content, "package_json")

    assert parsed == {
        "express": "^4.19.2",
        "react": "^18.3.1",
        "typescript": "^5.4.5",
        "eslint": "^9.0.0",
    }


def test_npm_parse_package_lock_v3():
    content = Path("tests/fixtures/npm/package-lock-v3.json").read_text(encoding="utf-8")

    parsed = NpmAdapter.parse_npm_lockfile(content)

    assert parsed == {
        "lodash": "4.17.21",
        "@scope/pkg": "1.2.3",
    }


def test_npm_parse_package_lock_v1():
    content = Path("tests/fixtures/npm/package-lock-v1.json").read_text(encoding="utf-8")

    parsed = NpmAdapter.parse_npm_lockfile(content)

    assert parsed == {
        "react": "18.2.0",
        "loose-envify": "1.4.0",
    }


def test_npm_parse_yarn_lock_v1():
    content = Path("tests/fixtures/npm/yarn-v1.lock").read_text(encoding="utf-8")

    parsed = NpmAdapter.parse_yarn_lockfile(content)

    assert parsed == {
        "lodash": "4.17.21",
        "@scope/pkg": "1.2.3",
    }


def test_npm_parse_yarn_lock_berry():
    content = Path("tests/fixtures/npm/yarn-berry.lock").read_text(encoding="utf-8")

    parsed = NpmAdapter.parse_yarn_lockfile(content)

    assert parsed == {
        "lodash": "4.17.21",
        "@scope/pkg": "1.2.3",
    }


def test_npm_parse_pnpm_lock():
    content = Path("tests/fixtures/npm/pnpm-lock.yaml").read_text(encoding="utf-8")

    parsed = NpmAdapter.parse_pnpm_lockfile(content)

    assert parsed == {
        "lodash": "4.17.21",
        "@scope/pkg": "1.2.3",
    }


def test_npm_lockfile_parsers_return_empty_dict_on_malformed_input():
    garbage = "{ definitely not a lockfile"

    assert NpmAdapter.parse_npm_lockfile(garbage) == {}
    assert NpmAdapter.parse_yarn_lockfile(garbage) == {}
    assert NpmAdapter.parse_pnpm_lockfile(garbage) == {}


def test_npm_adapter_writes_package_json_preserving_formatting(tmp_path):
    manifest_path = tmp_path / "package.json"
    original = Path("tests/fixtures/npm/package-format.json").read_text(encoding="utf-8")
    manifest_path.write_text(original, encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="package_json",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )

    NpmAdapter().write_manifest(
        manifest,
        [apply_module.UpgradeSelection("@scope/pkg", "1.0.0", "2.0.0")],
        original,
    )

    assert manifest_path.read_text(encoding="utf-8") == (
        "{\n"
        "    \"name\": \"demo-app\",\n"
        "    \"dependencies\": {\n"
        "        \"@scope/pkg\": \"2.0.0\",\n"
        "        \"left-pad\": \"^1.3.0\"\n"
        "    },\n"
        "    \"scripts\": {\n"
        "        \"build\": \"tsc -p .\"\n"
        "    }\n"
        "}\n"
    )


def test_npm_adapter_writes_package_json_updates_all_sections(tmp_path):
    manifest_path = tmp_path / "package.json"
    original = (
        "{\n"
        "  \"dependencies\": {\n"
        "    \"react\": \"^18.0.0\"\n"
        "  },\n"
        "  \"devDependencies\": {\n"
        "    \"react\": \"^18.0.0\"\n"
        "  }\n"
        "}\n"
    )
    manifest_path.write_text(original, encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="package_json",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )

    NpmAdapter().write_manifest(
        manifest,
        [apply_module.UpgradeSelection("react", "18.0.0", "19.0.0")],
        original,
    )

    assert manifest_path.read_text(encoding="utf-8").count('"react": "19.0.0"') == 2


def test_npm_registry_client_returns_currency_record(monkeypatch):
    class FakeSession:
        def get(self, url, timeout=30):
            return _FakeJSONResponse(
                200,
                {
                    "dist-tags": {"latest": "1.2.0"},
                    "time": {
                        "1.0.0": "2024-01-01T00:00:00.000Z",
                        "1.1.0": "2024-02-01T00:00:00.000Z",
                        "1.2.0": "2024-03-01T00:00:00.000Z",
                    },
                    "versions": {
                        "1.2.0": {"deprecated": "legacy"},
                    },
                },
            )

        def head(self, url, timeout=30):
            return _FakeJSONResponse(200, {})

    monkeypatch.setattr("src.ecosystem.npm_adapter.requests.Session", lambda: FakeSession())

    adapter = NpmAdapter()
    records = adapter.fetch_currency(["left-pad"], None)

    assert len(records) == 1
    assert records[0].package == "left-pad"
    assert records[0].latest_version == "1.2.0"
    assert records[0].deprecated is True
    assert "deprecated" in records[0].signals


def test_npm_lockfile_regeneration_returns_clear_error_when_npm_missing(
    monkeypatch, tmp_path
):
    manifest_path = tmp_path / "package.json"
    lockfile_path = tmp_path / "package-lock.json"
    manifest_path.write_text('{"name":"demo"}', encoding="utf-8")
    lockfile_path.write_text('{"lockfileVersion":3}', encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="package_json",
        has_lockfile=True,
        lockfile_path=lockfile_path,
        lockfile_type="npm_lockfile",
    )
    monkeypatch.setattr("src.ecosystem.npm_adapter.shutil.which", lambda tool: None)

    outcome = NpmAdapter().regenerate_lockfile(manifest)

    assert outcome.success is False
    assert "npm not found on PATH" in outcome.output


def test_npm_dry_run_validate_rejects_nonexistent_version(monkeypatch, tmp_path):
    class FakeSession:
        def get(self, url, timeout=30):
            return _FakeJSONResponse(
                200,
                {
                    "versions": {
                        "18.2.0": {"peerDependencies": {}},
                    }
                },
            )

        def head(self, url, timeout=30):
            return _FakeJSONResponse(404, {})

    monkeypatch.setattr("src.ecosystem.npm_adapter.requests.Session", lambda: FakeSession())
    manifest_path = tmp_path / "package.json"
    manifest_path.write_text(
        '{"dependencies":{"react":"^18.2.0"}}',
        encoding="utf-8",
    )
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="package_json",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )

    ok, message = NpmAdapter().dry_run_validate(
        manifest,
        [apply_module.UpgradeSelection("react", "18.2.0", "19.0.0")],
        None,
    )

    assert ok is False
    assert "react@19.0.0" in message


def test_js_usage_collects_named_imports():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"lodash": "^4.17.21"},
    )

    named_records = [
        record for record in result.records if record.source_file == "named_imports.js"
    ]

    assert {(record.package, record.symbol) for record in named_records} == {
        ("lodash", "foo"),
        ("lodash", "bar"),
    }


def test_js_usage_resolves_scoped_packages():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"@aws-sdk/client-s3": "^3.0.0"},
    )

    scoped = [record for record in result.records if record.source_file == "scoped_import.js"]
    assert len(scoped) == 1
    assert scoped[0].package == "@aws-sdk/client-s3"


def test_js_usage_resolves_subpath_specifiers():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"lodash": "^4.17.21"},
    )

    subpath = [record for record in result.records if record.source_file == "subpath_import.js"]
    assert len(subpath) == 1
    assert subpath[0].package == "lodash"


def test_js_usage_records_commonjs_require():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"left-pad": "^1.3.0"},
    )

    commonjs = [record for record in result.records if record.source_file == "commonjs.js"]
    assert {(record.package, record.symbol) for record in commonjs} == {
        ("left-pad", "default"),
        ("left-pad", "padLeft"),
    }


def test_js_usage_flags_dynamic_require():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"left-pad": "^1.3.0"},
    )

    assert any(
        item["flag"] == "dynamic_require" and item["source_file"] == "dynamic_require.js"
        for item in result.unresolved
    )


def test_js_usage_skips_relative_imports():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"local": "^1.0.0"},
    )

    assert not any(record.source_file == "relative_import.js" for record in result.records)


def test_js_usage_skips_node_builtins():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"fs": "^1.0.0"},
    )

    assert not any(record.source_file == "builtin_import.js" for record in result.records)


def test_js_usage_handles_typescript_syntax():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage"),
        {"@scope/pkg": "^1.0.0", "lib": "^1.0.0"},
    )

    ts_records = [record for record in result.records if record.source_file == "typed.ts"]
    assert {(record.package, record.symbol) for record in ts_records} >= {
        ("@scope/pkg", "Foo"),
        ("lib", "*"),
    }
    assert any(
        item["flag"] == "member_access" and item["package"] == "lib"
        for item in result.unresolved
    )


def test_js_usage_skips_node_modules_and_dist():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage/skip_project"),
        {"lodash": "^4.17.21"},
    )

    assert [record.source_file for record in result.records] == ["app.js"]


def test_js_usage_respects_gitignore():
    result = analyse_js_project(
        Path("tests/fixtures/npm/usage/gitignore_project"),
        {"lodash": "^4.17.21"},
    )

    assert [record.source_file for record in result.records] == ["app.js"]


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


def test_build_graph_packages_includes_installed_packages_for_cve_runs():
    graph_packages = _build_graph_packages(
        {"requests": ">=2.28.0", "flask": None},
        venv_pkgs={"requests": "2.32.5", "urllib3": "2.5.0", "black": "25.9.0"},
        include_installed=True,
    )

    assert graph_packages == {
        "requests": ">=2.28.0",
        "flask": None,
        "urllib3": "2.5.0",
        "black": "25.9.0",
    }


def test_build_graph_packages_keeps_manifest_only_when_not_requested():
    graph_packages = _build_graph_packages(
        {"requests": ">=2.28.0", "flask": None},
        venv_pkgs={"urllib3": "2.5.0", "black": "25.9.0"},
        include_installed=False,
    )

    assert graph_packages == {"requests": ">=2.28.0", "flask": None}


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


def test_render_dot_graph_uses_top_down_layout_defaults():
    dot_graph = render_dot_graph(
        [{"parent": "demo", "child": "requests"}],
        graph_name="demo",
    )

    assert 'rankdir="TB";' in dot_graph
    assert 'outputorder="edgesfirst";' in dot_graph
    assert 'fontname="Helvetica,Arial,sans-serif";' in dot_graph
    assert 'nodesep="0.35";' in dot_graph
    assert 'ranksep="0.6";' in dot_graph
    assert 'penwidth="0.6"' in dot_graph
    assert 'color="#cbd5e1"' in dot_graph


def test_render_svg_graph_uses_twopi_for_wide_shallow_graph(monkeypatch):
    edges = [
        {"parent": "demo", "child": f"dep{i}"}
        for i in range(10)
    ]
    commands: list[list[str]] = []

    def fake_run(cmd, stdin):
        commands.append(cmd)
        return 0, '<svg xmlns="http://www.w3.org/2000/svg"></svg>'

    monkeypatch.setattr(graph_module, "_run", fake_run)

    svg = render_svg_graph(edges, graph_name="demo")

    assert svg == '<svg xmlns="http://www.w3.org/2000/svg"></svg>'
    assert commands == [["twopi", "-Tsvg"]]


def test_report_dependency_graph_uses_severity_states_not_upgrades(monkeypatch):
    captured: dict[str, object] = {}

    def fake_render_svg_graph(edges, *, graph_name="changes_ai", package_states=None, rankdir=None):
        captured["edges"] = edges
        captured["package_states"] = package_states
        return "<svg><text>graph</text></svg>"

    monkeypatch.setattr(reporting_module, "render_svg_graph", fake_render_svg_graph)

    bundle = render_cached_html_report_bundle(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {"edges": [{"parent": "demo", "child": "requests"}]},
            "vulnerabilities": [
                {
                    "package": "requests",
                    "severity": "HIGH",
                    "cve_id": "CVE-1",
                    "installed_version": "2.31.0",
                    "fixed_versions": ["2.32.0"],
                }
            ],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [],
            "remediation_paths": [
                {
                    "path_type": "balanced",
                    "upgrades": [{"package": "requests"}],
                    "cves_no_fix": [],
                }
            ],
            "executive_summary": {},
        }
    )

    assert captured["edges"] == [{"parent": "demo", "child": "requests"}]
    assert captured["package_states"] == {"requests": "high"}
    assert "<svg><text>graph</text></svg>" in bundle["index.html"]
    assert "High" in bundle["index.html"]


def test_report_dependency_graph_filters_irrelevant_nodes(monkeypatch):
    captured: dict[str, object] = {}

    def fake_render_svg_graph(edges, *, graph_name="changes_ai", package_states=None, rankdir=None):
        captured["edges"] = edges
        return "<svg><text>graph</text></svg>"

    monkeypatch.setattr(reporting_module, "render_svg_graph", fake_render_svg_graph)

    render_cached_html_report_bundle(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {
                "edges": [
                    {"parent": "demo", "child": "requests"},
                    {"parent": "requests", "child": "urllib3"},
                    {"parent": "demo", "child": "flask"},
                    {"parent": "flask", "child": "jinja2"},
                ]
            },
            "vulnerabilities": [
                {
                    "package": "urllib3",
                    "severity": "HIGH",
                    "cve_id": "CVE-1",
                    "installed_version": "2.5.0",
                    "fixed_versions": ["2.6.0"],
                }
            ],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [
                {
                    "package": "urllib3",
                    "installed_version": "2.5.0",
                    "candidate_version": "2.6.0",
                    "probable_breakage": "LOW",
                    "breakage_score": 0.2,
                    "confidence": "MEDIUM",
                }
            ],
            "remediation_paths": [],
            "executive_summary": {},
        }
    )

    assert captured["edges"] == [
        {"parent": "demo", "child": "requests"},
        {"parent": "requests", "child": "urllib3"},
    ]


def test_report_dependency_graph_uses_impact_summary_packages_only(monkeypatch):
    captured: dict[str, object] = {}

    def fake_render_svg_graph(edges, *, graph_name="changes_ai", package_states=None, rankdir=None):
        captured["edges"] = edges
        return "<svg><text>graph</text></svg>"

    monkeypatch.setattr(reporting_module, "render_svg_graph", fake_render_svg_graph)

    bundle = render_cached_html_report_bundle(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {
                "edges": [
                    {"parent": "demo", "child": "requests"},
                    {"parent": "requests", "child": "urllib3"},
                    {"parent": "demo", "child": "flask"},
                    {"parent": "flask", "child": "jinja2"},
                ]
            },
            "vulnerabilities": [
                {
                    "package": "urllib3",
                    "severity": "HIGH",
                    "cve_id": "CVE-1",
                    "installed_version": "2.5.0",
                    "fixed_versions": ["2.6.0"],
                },
                {
                    "package": "flask",
                    "severity": "LOW",
                    "cve_id": "CVE-2",
                    "installed_version": "3.1.2",
                    "fixed_versions": ["3.1.3"],
                },
            ],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [
                {
                    "package": "urllib3",
                    "installed_version": "2.5.0",
                    "candidate_version": "2.6.0",
                    "probable_breakage": "LOW",
                    "breakage_score": 0.2,
                    "confidence": "MEDIUM",
                }
            ],
            "remediation_paths": [],
            "executive_summary": {},
        }
    )

    assert captured["edges"] == [
        {"parent": "demo", "child": "requests"},
        {"parent": "requests", "child": "urllib3"},
    ]
    assert "High" in bundle["index.html"]
    assert "Low" not in bundle["index.html"]


def test_dependency_graph_key_renders_severity_and_no_fix_states():
    key_html = reporting_module._render_dependency_graph_key(
        {
            "vulnerabilities": [
                {
                    "package": "requests",
                    "severity": "HIGH",
                    "cve_id": "CVE-1",
                },
                {
                    "package": "flask",
                    "severity": "CRITICAL",
                    "cve_id": "CVE-2",
                },
            ],
            "remediation_paths": [
                {
                    "path_type": "balanced",
                    "upgrades": [{"package": "requests"}],
                    "cves_no_fix": ["CVE-2"],
                }
            ],
        }
    )

    assert key_html is not None
    assert "High" in key_html
    assert "No fix available" in key_html
    assert "Upgraded" not in key_html


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


def test_report_html_repairs_broken_table_cell_tags():
    html = render_report_html(
        """# Changes AI Remediation Report

## Executive Summary

- Run ID: 1
- Target: demo
- Packages analysed: 1
- Vulnerabilities found: 0
- Remediation paths: 0

## Impact Summary

<table>
  <tr><th>Upgrade</th><th>Delta</th></tr>
  <tr><td>pytest 8.4.2 -&gt; 9.0.3/td><td>major</td></tr>
</table>
"""
    )

    assert "<td>pytest 8.4.2 -&gt; 9.0.3</td><td>major</td>" in html


def test_cached_html_report_bundle_links_osv_vulnerability_ids():
    bundle = render_cached_html_report_bundle(
        {
            "run": {"id": 1, "locator": "demo"},
            "packages": [{"name": "requests"}],
            "currency": [],
            "graph": {"edges": []},
            "vulnerabilities": [
                {
                    "package": "requests",
                    "severity": "HIGH",
                    "cve_id": "GHSA-9wx4-h78v-vm56",
                    "installed_version": "2.31.0",
                    "fixed_versions": ["2.32.0"],
                }
            ],
            "usage": {"records": [], "unresolved": []},
            "impact_reports": [],
            "remediation_paths": [],
            "executive_summary": {},
        }
    )

    assert (
        'href="https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56"'
        in bundle["index.html"]
    )
    assert 'target="_blank"' in bundle["index.html"]
    assert 'rel="noopener noreferrer"' in bundle["index.html"]
    assert (
        '>GHSA-9wx4-h78v-vm56<img class="external-link-icon" '
        'src="data:image/svg+xml;utf8,'
    ) in bundle["index.html"]
    assert 'alt="" aria-hidden="true"></a>' in bundle["index.html"]


def test_cached_html_report_bundle_embeds_graphviz_svg(monkeypatch):
    monkeypatch.setattr(
        reporting_module,
        "render_svg_graph",
        lambda edges, graph_name="changes_ai", **kwargs: "<svg><text>graph</text></svg>",
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


def test_render_dot_report_uses_severity_states_not_upgrades(monkeypatch):
    captured: dict[str, object] = {}

    def fake_render_dot_graph(edges, *, graph_name="changes_ai", package_states=None, rankdir=None):
        captured["edges"] = edges
        captured["package_states"] = package_states
        return "digraph G {}"

    monkeypatch.setattr(reporting_module, "render_dot_graph", fake_render_dot_graph)

    dot_graph = reporting_module.render_dot_report(
        {
            "run": {"id": 1, "locator": "demo"},
            "graph": {"edges": [{"parent": "demo", "child": "requests"}]},
            "vulnerabilities": [
                {
                    "package": "requests",
                    "severity": "HIGH",
                    "cve_id": "CVE-1",
                    "installed_version": "2.31.0",
                    "fixed_versions": ["2.32.0"],
                }
            ],
            "remediation_paths": [
                {
                    "path_type": "balanced",
                    "upgrades": [{"package": "requests"}],
                    "cves_no_fix": [],
                }
            ],
        }
    )

    assert dot_graph == "digraph G {}"
    assert captured["edges"] == [{"parent": "demo", "child": "requests"}]
    assert captured["package_states"] == {"requests": "high"}


def test_render_sarif_report_uses_project_information_uri():
    sarif = json.loads(
        reporting_module.render_sarif_report(
            {
                "run": {},
                "vulnerabilities": [],
                "remediation_paths": [],
                "currency": [],
            }
        )
    )

    assert (
        sarif["runs"][0]["tool"]["driver"]["informationUri"]
        == "https://github.com/pzanna/changes-ai"
    )


def test_pyproject_registers_changes_ai_package_dir():
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

    assert 'changes-ai = "changes_ai.changes_ai:main"' in pyproject
    assert '[tool.setuptools]' in pyproject
    assert '"changes_ai"' in pyproject
    assert '"changes_ai.ecosystem"' in pyproject
    assert '[tool.setuptools.package-dir]' in pyproject
    assert 'changes_ai = "src"' in pyproject


def test_apply_python_writes_requirements_preserving_comments(tmp_path):
    manifest_path = tmp_path / "requirements.txt"
    original = (
        "# base deps\n"
        "requests>=2.28.0  # keep this comment\n"
        "\n"
        "-r other.txt\n"
        "Flask==2.0.0\n"
        "urllib3>=2.0.0\n"
    )
    manifest_path.write_text(original, encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )

    PythonAdapter().write_manifest(
        manifest,
        [
            apply_module.UpgradeSelection("requests", "2.28.0", "2.32.3"),
            apply_module.UpgradeSelection("flask", "2.0.0", "2.3.3"),
        ],
        original,
    )

    assert manifest_path.read_text(encoding="utf-8") == (
        "# base deps\n"
        "requests==2.32.3  # keep this comment\n"
        "\n"
        "-r other.txt\n"
        "Flask==2.3.3\n"
        "urllib3>=2.0.0\n"
    )


def test_apply_python_writes_pyproject_preserving_formatting(tmp_path):
    manifest_path = tmp_path / "pyproject.toml"
    original = (
        "[project]\n"
        "name = \"demo\"\n"
        "dependencies = [\n"
        "    \"requests>=2.28.0\",\n"
        "    \"urllib3>=2.0.0\", # keep comment\n"
        "]\n"
        "\n"
        "[tool.poetry.dependencies]\n"
        "python = \"^3.11\"\n"
        "Flask = \"^2.0.0\"\n"
        "rich = { version = \"^13.0\", optional = true }\n"
    )
    manifest_path.write_text(original, encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pyproject",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )

    PythonAdapter().write_manifest(
        manifest,
        [
            apply_module.UpgradeSelection("requests", "2.28.0", "2.32.3"),
            apply_module.UpgradeSelection("flask", "2.0.0", "2.3.3"),
            apply_module.UpgradeSelection("rich", "13.0", "13.9.4"),
        ],
        original,
    )

    assert manifest_path.read_text(encoding="utf-8") == (
        "[project]\n"
        "name = \"demo\"\n"
        "dependencies = [\n"
        "    \"requests==2.32.3\",\n"
        "    \"urllib3>=2.0.0\", # keep comment\n"
        "]\n"
        "\n"
        "[tool.poetry.dependencies]\n"
        "python = \"^3.11\"\n"
        "Flask = \"==2.3.3\"\n"
        "rich = { version = \"==13.9.4\", optional = true }\n"
    )


def test_apply_snapshot_restore_round_trip(tmp_path):
    manifest_path = tmp_path / "requirements.txt"
    lockfile_path = tmp_path / "uv.lock"
    manifest_path.write_text("requests>=2.28.0\n", encoding="utf-8")
    lockfile_path.write_text("version = 1\n", encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=True,
        lockfile_path=lockfile_path,
        lockfile_type="uv_lockfile",
    )

    snap = apply_module.snapshot(manifest, None)
    manifest_path.write_text("requests==9.9.9\n", encoding="utf-8")
    lockfile_path.write_text("version = 2\n", encoding="utf-8")
    apply_module.restore(snap)

    assert manifest_path.read_text(encoding="utf-8") == "requests>=2.28.0\n"
    assert lockfile_path.read_text(encoding="utf-8") == "version = 1\n"


def test_apply_dry_run_failure_does_not_write_manifest(monkeypatch, tmp_path):
    manifest_path = tmp_path / "requirements.txt"
    original = "requests>=2.28.0\n"
    manifest_path.write_text(original, encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )
    adapter = PythonAdapter()
    monkeypatch.setattr(
        adapter,
        "dry_run_validate",
        lambda manifest, upgrades, environment_root: (False, "conflict"),
    )

    result = apply_module.apply_remediation(
        adapter,
        manifest,
        [apply_module.UpgradeSelection("requests", "2.28.0", "2.32.3")],
    )

    assert result.success is False
    assert result.error == "conflict"
    assert manifest_path.read_text(encoding="utf-8") == original


def test_apply_install_failure_restores_snapshot(monkeypatch, tmp_path):
    manifest_path = tmp_path / "requirements.txt"
    original = "requests>=2.28.0\n"
    manifest_path.write_text(original, encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )
    adapter = PythonAdapter()
    monkeypatch.setattr(
        adapter,
        "dry_run_validate",
        lambda manifest, upgrades, environment_root: (True, ""),
    )
    monkeypatch.setattr(
        adapter,
        "install",
        lambda manifest, upgrades, environment_root: ApplyOutcome(
            success=False,
            output="boom",
            files_modified=[],
        ),
    )

    result = apply_module.apply_remediation(
        adapter,
        manifest,
        [apply_module.UpgradeSelection("requests", "2.28.0", "2.32.3")],
    )

    assert result.success is False
    assert manifest_path.read_text(encoding="utf-8") == original


def test_apply_lockfile_regeneration_failure_restores_snapshot(monkeypatch, tmp_path):
    manifest_path = tmp_path / "requirements.txt"
    lockfile_path = tmp_path / "uv.lock"
    original = "requests>=2.28.0\n"
    manifest_path.write_text(original, encoding="utf-8")
    lockfile_path.write_text("old lock\n", encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=True,
        lockfile_path=lockfile_path,
        lockfile_type="uv_lockfile",
    )
    adapter = PythonAdapter()
    monkeypatch.setattr(
        adapter,
        "dry_run_validate",
        lambda manifest, upgrades, environment_root: (True, ""),
    )

    def _fail_lockfile(_manifest):
        lockfile_path.write_text("new lock\n", encoding="utf-8")
        return ApplyOutcome(success=False, output="lock failed", files_modified=[])

    monkeypatch.setattr(adapter, "regenerate_lockfile", _fail_lockfile)

    result = apply_module.apply_remediation(
        adapter,
        manifest,
        [apply_module.UpgradeSelection("requests", "2.28.0", "2.32.3")],
    )

    assert result.success is False
    assert manifest_path.read_text(encoding="utf-8") == original
    assert lockfile_path.read_text(encoding="utf-8") == "old lock\n"


def test_apply_lockfile_regeneration_returns_clear_error_when_uv_missing(
    monkeypatch, tmp_path
):
    manifest_path = tmp_path / "requirements.txt"
    lockfile_path = tmp_path / "uv.lock"
    manifest_path.write_text("requests>=2.28.0\n", encoding="utf-8")
    lockfile_path.write_text("lock\n", encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=True,
        lockfile_path=lockfile_path,
        lockfile_type="uv_lockfile",
    )
    monkeypatch.setattr("src.ecosystem.python_adapter.shutil.which", lambda tool: None)

    outcome = PythonAdapter().regenerate_lockfile(manifest)

    assert outcome.success is False
    assert "uv not found on PATH" in outcome.output


def test_apply_remediation_dry_run_api_succeeds_for_python_project(
    monkeypatch, tmp_path
):
    (tmp_path / "requirements.txt").write_text("requests>=2.28.0\n", encoding="utf-8")
    adapter = PythonAdapter()
    manifest = adapter.find_manifest(tmp_path)
    assert manifest is not None
    monkeypatch.setattr(
        adapter,
        "dry_run_validate",
        lambda manifest, upgrades, environment_root: (True, ""),
    )

    result = apply_module.apply_remediation(
        adapter,
        manifest,
        [apply_module.UpgradeSelection("requests", "2.28.0", "2.32.3")],
        dry_run_only=True,
    )

    assert result.success is True
    assert result.dry_run is True
    assert result.files_modified == []


def test_editor_build_state_starts_with_all_upgrades_selected():
    path = RemediationPath(
        path_type="balanced",
        upgrades=[
            RemediationUpgrade("requests", "2.31.0", "2.32.0", ["CVE-1"]),
            RemediationUpgrade("urllib3", "2.5.0", "2.6.0", ["CVE-2"]),
        ],
        cves_resolved=["CVE-1", "CVE-2"],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.2,
        confidence="HIGH",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], [], [])

    assert len(state.tabs) == 1
    tab = state.tabs[0]
    assert tab.path_type == "balanced"
    assert {u.package for u in tab.upgrades} == {"requests", "urllib3"}
    assert "requests" in tab.selected
    assert "urllib3" in tab.selected
    assert state.active_tab_index == 0
    assert state.cursor_index == 0


def test_editor_recalculate_matches_remediation_module():
    vulns = [
        VulnerabilityRecord("requests", "2.31.0", "CVE-1", "HIGH", [], ["2.32.0"]),
        VulnerabilityRecord("urllib3", "2.5.0", "CVE-2", "MEDIUM", [], ["2.6.0"]),
    ]
    reports = [
        ImpactReport(
            package="requests",
            installed_version="2.31.0",
            candidate_version="2.32.0",
            version_delta="minor",
            probable_breakage="LOW",
            breakage_score=0.2,
            confidence="HIGH",
        ),
        ImpactReport(
            package="urllib3",
            installed_version="2.5.0",
            candidate_version="2.6.0",
            version_delta="minor",
            probable_breakage="MEDIUM",
            breakage_score=0.3,
            confidence="MEDIUM",
        ),
    ]
    path = RemediationPath(
        path_type="balanced",
        upgrades=[
            RemediationUpgrade("requests", "2.31.0", "2.32.0", ["CVE-1"]),
            RemediationUpgrade("urllib3", "2.5.0", "2.6.0", ["CVE-2"]),
        ],
        cves_resolved=["CVE-1", "CVE-2"],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.3,
        confidence="MEDIUM",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], reports, vulns)
    context = state.context

    exposure, breakage, confidence = remediation_editor_module.recalculate_scores(state)
    expected = _compute_exposure_score([], [], context["severity_map"], context["total_weight"])

    assert exposure == round(expected, 3)
    assert breakage == 0.3
    assert confidence == "MEDIUM"


def test_editor_toggle_removes_package_from_selection():
    path = RemediationPath(
        path_type="balanced",
        upgrades=[RemediationUpgrade("requests", "2.31.0", "2.32.0", ["CVE-1"])],
        cves_resolved=["CVE-1"],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.2,
        confidence="HIGH",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], [], [])
    assert "requests" in state.tabs[0].selected

    remediation_editor_module.toggle_current(state)

    assert "requests" not in state.tabs[0].selected


def test_editor_toggle_returns_constraint_message_on_violation():
    report = ImpactReport(
        package="requests",
        installed_version="2.31.0",
        candidate_version="2.33.0",
        version_delta="minor",
        probable_breakage="LOW",
        breakage_score=0.2,
        confidence="HIGH",
    )
    path = RemediationPath(
        path_type="balanced",
        upgrades=[
            RemediationUpgrade("requests", "2.31.0", "2.33.0", []),
            RemediationUpgrade("urllib3", "2.5.0", "2.5.0", []),
        ],
        cves_resolved=[],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.2,
        confidence="HIGH",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], [report], [])
    state.context["reports"] = {
        ("requests", "2.31.0", "2.33.0"): {
            "report": report,
            "dependency_constraints": {"urllib3": ">=2.6.0"},
        }
    }
    # cursor is at requests (index 0) — toggle it off then back on triggers check
    remediation_editor_module.toggle_current(state)   # deselect requests
    remediation_editor_module.toggle_current(state)   # reselect requests — triggers constraint check

    messages = state.last_constraint_messages
    assert messages
    assert "requests" in messages[0]
    assert "urllib3" in messages[0]


def test_editor_switch_tab_resets_cursor():
    paths = [
        RemediationPath(
            path_type="balanced",
            upgrades=[
                RemediationUpgrade("requests", "2.31.0", "2.32.0", []),
                RemediationUpgrade("urllib3", "2.5.0", "2.6.0", []),
            ],
            cves_resolved=[],
            cves_unresolved=[],
            cves_no_fix=[],
            exposure_score=0.1,
            breakage_score=0.2,
            confidence="HIGH",
            rationale="",
        ),
        RemediationPath(
            path_type="maximum_coverage",
            upgrades=[RemediationUpgrade("certifi", "2023.0.0", "2024.0.0", [])],
            cves_resolved=[],
            cves_unresolved=[],
            cves_no_fix=[],
            exposure_score=0.05,
            breakage_score=0.1,
            confidence="HIGH",
            rationale="",
        ),
    ]
    state = remediation_editor_module.build_editor_state(paths, [], [])
    remediation_editor_module.move_cursor(state, 1)
    assert state.cursor_index == 1

    remediation_editor_module.switch_tab(state, 1)

    assert state.cursor_index == 0
    assert state.active_tab_index == 1


def test_editor_reset_active_tab_restores_all_selected():
    path = RemediationPath(
        path_type="balanced",
        upgrades=[
            RemediationUpgrade("requests", "2.31.0", "2.32.0", []),
            RemediationUpgrade("urllib3", "2.5.0", "2.6.0", []),
        ],
        cves_resolved=[],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.2,
        confidence="HIGH",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], [], [])
    state.tabs[0].selected.clear()
    assert not state.tabs[0].selected

    remediation_editor_module.reset_active_tab(state)

    assert "requests" in state.tabs[0].selected
    assert "urllib3" in state.tabs[0].selected


def test_editor_collect_selected_upgrades_preserves_order():
    path = RemediationPath(
        path_type="balanced",
        upgrades=[
            RemediationUpgrade("aaa", "1.0.0", "1.1.0", []),
            RemediationUpgrade("bbb", "2.0.0", "2.1.0", []),
            RemediationUpgrade("ccc", "3.0.0", "3.1.0", []),
        ],
        cves_resolved=[],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.1,
        confidence="HIGH",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], [], [])
    state.tabs[0].selected.discard("bbb")

    result = remediation_editor_module.collect_selected_upgrades(state)

    assert [u.package for u in result] == ["aaa", "ccc"]


def test_editor_skips_when_not_tty(monkeypatch, tmp_path):
    manifest_path = tmp_path / "requirements.txt"
    manifest_path.write_text("requests>=2.28.0\n", encoding="utf-8")
    manifest = ManifestInfo(
        path=manifest_path,
        file_type="pip",
        has_lockfile=False,
        lockfile_path=None,
        lockfile_type=None,
    )
    path = RemediationPath(
        path_type="balanced",
        upgrades=[RemediationUpgrade("requests", "2.28.0", "2.32.3", [])],
        cves_resolved=[],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.1,
        confidence="HIGH",
        rationale="",
    )
    state = remediation_editor_module.build_editor_state([path], [], [])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    modules_before = set(sys.modules)
    result = remediation_editor_module.run_editor(state, PythonAdapter(), manifest)
    new_modules = set(sys.modules) - modules_before

    assert result.action == "skipped"
    assert result.apply_result is None
    assert not any("prompt_toolkit" in m for m in new_modules)


def test_editor_help_text_for_cursor_includes_evidence():
    report = ImpactReport(
        package="requests",
        installed_version="2.31.0",
        candidate_version="2.32.0",
        version_delta="minor",
        probable_breakage="LOW",
        breakage_score=0.1,
        confidence="HIGH",
        evidence="No breaking changes detected. API is stable.",
    )
    path = RemediationPath(
        path_type="balanced",
        upgrades=[RemediationUpgrade("requests", "2.31.0", "2.32.0", ["CVE-1"])],
        cves_resolved=["CVE-1"],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.1,
        confidence="HIGH",
        rationale="",
    )
    vulns = [VulnerabilityRecord("requests", "2.31.0", "CVE-1", "HIGH", [], ["2.32.0"])]
    state = remediation_editor_module.build_editor_state([path], [report], vulns)

    text = remediation_editor_module.help_text_for_cursor(state)

    assert "requests" in text
    assert "CVE-1" in text
    assert "Evidence" in text
    assert "No breaking changes" in text


def test_editor_render_helpers_produce_formatted_text():
    path = RemediationPath(
        path_type="balanced",
        upgrades=[RemediationUpgrade("requests", "2.31.0", "2.32.0", ["CVE-1"])],
        cves_resolved=["CVE-1"],
        cves_unresolved=[],
        cves_no_fix=[],
        exposure_score=0.1,
        breakage_score=0.2,
        confidence="HIGH",
        rationale="",
    )
    vulns = [VulnerabilityRecord("requests", "2.31.0", "CVE-1", "HIGH", [], ["2.32.0"])]
    state = remediation_editor_module.build_editor_state([path], [], vulns)

    tab_bar = remediation_editor_module._render_tab_bar(state)
    selection = remediation_editor_module._render_selection(state)
    scores = remediation_editor_module._render_scores_bar(state)
    keybindings = remediation_editor_module._render_keybindings_bar()

    # All renderers return list of (style, text) tuples
    for result in (tab_bar, selection, scores, keybindings):
        assert isinstance(result, list)
        assert all(isinstance(item, tuple) and len(item) == 2 for item in result)

    tab_text = "".join(t for _, t in tab_bar)
    assert "Balanced" in tab_text

    sel_text = "".join(t for _, t in selection)
    assert "requests" in sel_text
    assert "[x]" in sel_text

    kb_text = "".join(t for _, t in keybindings)
    assert "toggle" in kb_text


def _run_main_with_args(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["changes-ai", *argv])
    try:
        changes_ai_module.main()
    except SystemExit as exc:
        return exc.code
    return 0


def _stub_cli_pipeline(monkeypatch):
    monkeypatch.setattr(changes_ai_module, "build_version_mapping", lambda packages, libraries_client, venv_pkgs=None: [
        {
            "name": name,
            "installed": "1.0.0",
            "requirement": requirement or "unpinned",
            "latest": "1.0.1",
            "status": "outdated",
        }
        for name, requirement in packages.items()
    ])
    monkeypatch.setattr(changes_ai_module, "analyse_currency", lambda mapping, libraries_client: [])
    monkeypatch.setattr(changes_ai_module, "scan_vulnerabilities", lambda *args, **kwargs: [])
    monkeypatch.setattr(changes_ai_module, "run_impact_analysis", lambda **kwargs: [])
    monkeypatch.setattr(
        changes_ai_module,
        "run_remediation_plan",
        lambda **kwargs: [
            RemediationPath(
                path_type="balanced",
                upgrades=[RemediationUpgrade("requests", "2.31.0", "2.32.0", ["CVE-1"])],
                cves_resolved=["CVE-1"],
                cves_unresolved=[],
                cves_no_fix=[],
                exposure_score=0.1,
                breakage_score=0.5,
                confidence="HIGH",
                rationale="",
            )
        ],
    )
    monkeypatch.setattr(changes_ai_module, "_generate_executive_summary_narrative", lambda *args, **kwargs: "")
    monkeypatch.setattr(changes_ai_module, "_resolve_report_output_path", lambda *args, **kwargs: None)


def test_cli_apply_requires_source(monkeypatch, capsys):
    code = _run_main_with_args(monkeypatch, ["--apply"])
    captured = capsys.readouterr()

    assert code == 0
    assert "--apply / --auto-apply requires --source" in captured.err


def test_cli_auto_apply_exits_3_when_breakage_exceeds_threshold(
    monkeypatch, tmp_path, capsys
):
    source = tmp_path / "project"
    source.mkdir()
    manifest = source / "requirements.txt"
    manifest.write_text("requests>=2.28.0\n", encoding="utf-8")
    _stub_cli_pipeline(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    code = _run_main_with_args(
        monkeypatch,
        [
            "--source",
            str(source),
            "--cache-db",
            str(tmp_path / "cache.db"),
            "--cve-scan",
            "--impact-analysis",
            "--plan",
            "--auto-apply",
            "balanced",
            "--max-breakage-score",
            "0.3",
        ],
    )
    captured = capsys.readouterr()

    assert code == 3
    assert "exceeds --max-breakage-score" in captured.err
    assert manifest.read_text(encoding="utf-8") == "requests>=2.28.0\n"


def test_cli_ecosystem_override_with_no_matching_manifest_exits_1(
    monkeypatch, tmp_path, capsys
):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['requests>=2.0']\n", encoding="utf-8")

    code = _run_main_with_args(
        monkeypatch,
        ["--source", str(tmp_path), "--ecosystem", "npm"],
    )
    captured = capsys.readouterr()

    assert code == 1
    assert "no matching manifest found" in captured.err


def test_cli_apply_in_non_tty_prints_note_and_skips(monkeypatch, tmp_path, capsys):
    source = tmp_path / "project"
    source.mkdir()
    (source / "requirements.txt").write_text("requests>=2.28.0\n", encoding="utf-8")
    _stub_cli_pipeline(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    code = _run_main_with_args(
        monkeypatch,
        [
            "--source",
            str(source),
            "--cache-db",
            str(tmp_path / "cache.db"),
            "--cve-scan",
            "--impact-analysis",
            "--plan",
            "--apply",
        ],
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "--apply ignored in non-interactive mode" in captured.err


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
