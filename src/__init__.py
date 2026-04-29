"""Public import surface for Changes AI.

The package root exposes a convenience API, but the exports are resolved lazily
to avoid importing the CLI module while submodules are still being imported.
"""

from __future__ import annotations

from importlib import import_module

__version__ = "0.7.0"

_EXPORTS = {
    "CacheMissError": ("src.cache", "CacheMissError"),
    "DependencyParser": ("src.changes_ai", "DependencyParser"),
    "LibrariesIOClient": ("src.changes_ai", "LibrariesIOClient"),
    "PipelineOrchestrator": ("src.pipeline", "PipelineOrchestrator"),
    "PipelineRun": ("src.pipeline", "PipelineRun"),
    "SQLiteCache": ("src.cache", "SQLiteCache"),
    "StageResult": ("src.pipeline", "StageResult"),
    "VenvParser": ("src.changes_ai", "VenvParser"),
    "analyse_currency": ("src.currency", "analyse_currency"),
    "build_dependency_edges": ("src.graph", "build_dependency_edges"),
    "build_version_mapping": ("src.changes_ai", "build_version_mapping"),
    "clone_github_repo": ("src.changes_ai", "clone_github_repo"),
    "default_cache_path": ("src.cache", "default_cache_path"),
    "find_venv": ("src.changes_ai", "find_venv"),
    "generate_ascii_chart": ("src.changes_ai", "generate_ascii_chart"),
    "generate_mermaid_chart": ("src.changes_ai", "generate_mermaid_chart"),
    "main": ("src.changes_ai", "main"),
    "parse_github_url": ("src.changes_ai", "parse_github_url"),
    "print_version_table": ("src.changes_ai", "print_version_table"),
    "render_dot_graph": ("src.graph", "render_dot_graph"),
    "render_dot_report": ("src.reporting", "render_dot_report"),
    "render_json_report": ("src.reporting", "render_json_report"),
    "render_markdown_report": ("src.reporting", "render_markdown_report"),
    "render_pdf_report": ("src.reporting", "render_pdf_report"),
    "render_sarif_report": ("src.reporting", "render_sarif_report"),
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
