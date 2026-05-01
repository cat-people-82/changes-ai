"""Public import surface for Changes AI.

The package root exposes a convenience API, but the exports are resolved lazily
to avoid importing the CLI module while submodules are still being imported.
"""

from __future__ import annotations

from importlib import import_module

__version__ = "0.7.0"

_PACKAGE_PREFIX = __name__

_EXPORTS = {
    "CacheMissError": (f"{_PACKAGE_PREFIX}.cache", "CacheMissError"),
    "DependencyParser": (f"{_PACKAGE_PREFIX}.changes_ai", "DependencyParser"),
    "LibrariesIOClient": (f"{_PACKAGE_PREFIX}.changes_ai", "LibrariesIOClient"),
    "PipelineOrchestrator": (f"{_PACKAGE_PREFIX}.pipeline", "PipelineOrchestrator"),
    "PipelineRun": (f"{_PACKAGE_PREFIX}.pipeline", "PipelineRun"),
    "SQLiteCache": (f"{_PACKAGE_PREFIX}.cache", "SQLiteCache"),
    "StageResult": (f"{_PACKAGE_PREFIX}.pipeline", "StageResult"),
    "VenvParser": (f"{_PACKAGE_PREFIX}.changes_ai", "VenvParser"),
    "analyse_currency": (f"{_PACKAGE_PREFIX}.currency", "analyse_currency"),
    "build_dependency_edges": (f"{_PACKAGE_PREFIX}.graph", "build_dependency_edges"),
    "build_version_mapping": (f"{_PACKAGE_PREFIX}.changes_ai", "build_version_mapping"),
    "clone_github_repo": (f"{_PACKAGE_PREFIX}.changes_ai", "clone_github_repo"),
    "default_cache_path": (f"{_PACKAGE_PREFIX}.cache", "default_cache_path"),
    "find_venv": (f"{_PACKAGE_PREFIX}.changes_ai", "find_venv"),
    "generate_ascii_chart": (f"{_PACKAGE_PREFIX}.changes_ai", "generate_ascii_chart"),
    "generate_mermaid_chart": (f"{_PACKAGE_PREFIX}.changes_ai", "generate_mermaid_chart"),
    "main": (f"{_PACKAGE_PREFIX}.changes_ai", "main"),
    "parse_github_url": (f"{_PACKAGE_PREFIX}.changes_ai", "parse_github_url"),
    "print_version_table": (f"{_PACKAGE_PREFIX}.changes_ai", "print_version_table"),
    "render_dot_graph": (f"{_PACKAGE_PREFIX}.graph", "render_dot_graph"),
    "render_dot_report": (f"{_PACKAGE_PREFIX}.reporting", "render_dot_report"),
    "render_json_report": (f"{_PACKAGE_PREFIX}.reporting", "render_json_report"),
    "render_markdown_report": (f"{_PACKAGE_PREFIX}.reporting", "render_markdown_report"),
    "render_pdf_report": (f"{_PACKAGE_PREFIX}.reporting", "render_pdf_report"),
    "render_sarif_report": (f"{_PACKAGE_PREFIX}.reporting", "render_sarif_report"),
}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _EXPORTS[name]
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_EXPORTS.keys()))


__all__ = [
    "__version__",
    "CacheMissError",
    "DependencyParser",
    "LibrariesIOClient",
    "PipelineOrchestrator",
    "PipelineRun",
    "SQLiteCache",
    "StageResult",
    "analyse_currency",
    "build_dependency_edges",
    "clone_github_repo",
    "render_dot_graph",
    "render_dot_report",
    "render_json_report",
    "render_markdown_report",
    "render_pdf_report",
    "render_sarif_report",
    "VenvParser",
    "build_version_mapping",
    "default_cache_path",
    "find_venv",
    "generate_ascii_chart",
    "generate_mermaid_chart",
    "main",
    "parse_github_url",
    "print_version_table",
]
