from __future__ import annotations

"""Report output path resolution and rendering helpers.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import io
import os
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path

try:
    from .cli_display import print_version_table
    from .reporting import (
        render_dot_report,
        render_html_report_bundle,
        render_json_report,
        render_markdown_report,
        render_pdf_report,
        render_sarif_report,
    )
except ImportError:  # pragma: no cover
    from src.cli_display import print_version_table
    from src.reporting import (
        render_dot_report,
        render_html_report_bundle,
        render_json_report,
        render_markdown_report,
        render_pdf_report,
        render_sarif_report,
    )


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def _env_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


# ---------------------------------------------------------------------------
# Report format constants
# ---------------------------------------------------------------------------

REPORT_FORMAT_EXTENSIONS = {
    "json": "json",
    "table": "txt",
    "md": "md",
    "html": "html",
    "pdf": "pdf",
    "sarif": "sarif",
    "dot": "dot",
}
REPORT_FORMAT_CHOICES = tuple(REPORT_FORMAT_EXTENSIONS)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _report_output_folder() -> Path | None:
    value = _env_value("CHANGES_AI_REPORT_PATH")
    return Path(value).expanduser() if value else None


def _timestamped_report_path(report_format: str, output_dir: str | Path) -> Path:
    extension = REPORT_FORMAT_EXTENSIONS.get(report_format, report_format)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if report_format == "html":
        output_path = Path(output_dir).expanduser() / f"report_{timestamp}"
    else:
        output_path = Path(output_dir).expanduser() / f"report_{timestamp}.{extension}"
    suffix = 1
    while output_path.exists():
        if report_format == "html":
            output_path = Path(output_dir).expanduser() / f"report_{timestamp}_{suffix}"
        else:
            output_path = (
                Path(output_dir).expanduser()
                / f"report_{timestamp}_{suffix}.{extension}"
            )
        suffix += 1
    return output_path


def _default_report_format(default: str = "json") -> str:
    value = _env_value("CHANGES_AI_REPORT_FORMAT")
    if not value:
        return default
    normalized = value.lower()
    return normalized if normalized in REPORT_FORMAT_EXTENSIONS else default


def _default_report_template() -> str | None:
    return _env_value("CHANGES_AI_REPORT_TEMPLATE")


def _is_output_directory(output_path: Path, requested_path: str) -> bool:
    """Return True if the output path should be treated as a directory.

    A path is treated as a directory only when it already exists as one,
    or when the user explicitly appended a path separator (e.g. ``reports/``).
    Every other path — including extensionless names like ``report`` — is
    treated as a plain file path so users are not surprised by automatic
    timestamped filenames.
    """
    return output_path.is_dir() or requested_path.endswith(("/", "\\"))


def _resolve_output_path(
    path: str, env_dir_var: str = "CHANGES_AI_REPORT_PATH"
) -> Path:
    output_path = Path(path).expanduser()
    output_dir = _env_value(env_dir_var)
    if output_dir and not output_path.is_absolute():
        output_path = Path(output_dir).expanduser() / output_path
    return output_path


def _resolve_report_output_path(
    report_format: str,
    requested_path: str | None = None,
) -> Path | None:
    if requested_path:
        output_path = Path(requested_path).expanduser()
        if _is_output_directory(output_path, requested_path):
            return _timestamped_report_path(report_format, output_path)
        return output_path

    output_folder = _report_output_folder()
    if output_folder is None:
        if report_format == "html":
            return _timestamped_report_path(report_format, Path.cwd())
        return None
    return _timestamped_report_path(report_format, output_folder)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _render_version_table(mapping: list) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_version_table(mapping)
    return buffer.getvalue().rstrip("\n")


def _render_cached_report(
    report: dict,
    report_format: str,
    run_id: int,
    report_template: str | None = None,
) -> str | bytes | dict[str, str]:
    if report_format == "json":
        return render_json_report(report)
    if report_format == "md":
        return render_markdown_report(report).rstrip("\n")
    if report_format == "html":
        return render_html_report_bundle(report, css_path=report_template)
    if report_format == "pdf":
        return render_pdf_report(report, css_path=report_template)
    if report_format == "sarif":
        return render_sarif_report(report)
    if report_format == "dot":
        return render_dot_report(report)
    if report_format == "table":
        return f"Run: {run_id}\n\n{_render_version_table(report['packages'])}"
    raise ValueError(f"Unsupported report format: {report_format}")


def _write_text_output(path: str | Path, content: str) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _write_report_output(path: str | Path, content: str | bytes) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        output_path.write_bytes(content)
    else:
        output_path.write_text(content, encoding="utf-8")
    return output_path


def _write_html_report_output(path: str | Path, bundle: dict[str, str]) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.mkdir(parents=True, exist_ok=True)
    for name, content in bundle.items():
        (output_path / name).write_text(content, encoding="utf-8")
    return output_path
