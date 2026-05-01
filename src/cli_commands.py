from __future__ import annotations

"""CLI sub-commands: cache and report.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import argparse
import sys

try:
    from .cache import SQLiteCache, default_cache_path
    from .cli_display import _print_cache_entries, print_version_table
    from .cli_report import (
        REPORT_FORMAT_CHOICES,
        _default_report_format,
        _default_report_template,
        _render_cached_report,
        _resolve_report_output_path,
        _timestamped_report_path,
        _write_html_report_output,
        _write_report_output,
    )
except ImportError:  # pragma: no cover
    from src.cache import SQLiteCache, default_cache_path
    from src.cli_display import _print_cache_entries, print_version_table
    from src.cli_report import (
        REPORT_FORMAT_CHOICES,
        _default_report_format,
        _default_report_template,
        _render_cached_report,
        _resolve_report_output_path,
        _timestamped_report_path,
        _write_html_report_output,
        _write_report_output,
    )
from pathlib import Path


def _run_cache_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="changes-ai cache",
        description="Inspect or clear the Changes AI SQLite cache.",
    )
    parser.add_argument(
        "--cache-db",
        default=str(default_cache_path()),
        help=(
            "Path to the SQLite cache database. Defaults to CHANGES_AI_CACHE_DB "
            "when set."
        ),
    )
    subparsers = parser.add_subparsers(dest="cache_action", required=True)
    list_parser = subparsers.add_parser("list", help="List cached API entries.")
    list_parser.add_argument(
        "--cache-db",
        default=argparse.SUPPRESS,
        help="Path to the SQLite cache database.",
    )
    clear_parser = subparsers.add_parser("clear", help="Clear cached API entries.")
    clear_parser.add_argument(
        "--cache-db",
        default=argparse.SUPPRESS,
        help="Path to the SQLite cache database.",
    )
    clear_parser.add_argument(
        "--source",
        help="Only clear one cache source, e.g. libraries_io_package.",
    )
    args = parser.parse_args(argv)

    cache = SQLiteCache(args.cache_db)
    try:
        if args.cache_action == "list":
            _print_cache_entries(cache)
        elif args.cache_action == "clear":
            removed = cache.clear(source=args.source)
            print(f"Removed {removed} cache entr{'y' if removed == 1 else 'ies'}.")
    finally:
        cache.close()


def _run_report_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="changes-ai report",
        description="Render cached run data without re-running the scan.",
    )
    parser.add_argument(
        "run_id", nargs="?", type=int, help="Run ID to report; defaults to latest run."
    )
    parser.add_argument(
        "--format",
        choices=REPORT_FORMAT_CHOICES,
        default=_default_report_format("json"),
        help=(
            "Report output format. Defaults to CHANGES_AI_REPORT_FORMAT when set, "
            "otherwise json."
        ),
    )
    parser.add_argument(
        "--report-template",
        default=_default_report_template(),
        help=(
            "PDF report template name or path to a CSS file. Defaults to "
            "CHANGES_AI_REPORT_TEMPLATE when set, otherwise the built-in template."
        ),
    )
    parser.add_argument(
        "--cache-db",
        default=str(default_cache_path()),
        help=(
            "Path to the SQLite cache database. Defaults to CHANGES_AI_CACHE_DB "
            "when set."
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
        help=(
            "Write the rendered report to a file or directory. Existing directory "
            "outputs use report_YYYYMMDD_HHMMSS with the selected format extension; "
            "html reports create a folder containing index.html and style.css. "
            "When omitted, CHANGES_AI_REPORT_PATH is used as the report "
            "directory if set; otherwise the report is written to stdout."
        ),
    )
    args = parser.parse_args(argv)
    cache = SQLiteCache(args.cache_db)
    try:
        run_id = args.run_id if args.run_id is not None else cache.latest_run_id()
        if run_id is None:
            print("No cached runs found.")
            return
        report = cache.get_run_report(run_id)
        if report is None:
            print(f"No cached run found for run ID {run_id}.", file=sys.stderr)
            sys.exit(1)
        output_path = _resolve_report_output_path(args.format, args.output)

        rendered = _render_cached_report(
            report,
            args.format,
            run_id,
            report_template=args.report_template,
        )
        if args.format == "table" and output_path is None:
            print(f"Run: {run_id}\n")
            print_version_table(report["packages"])
            return

        if args.format == "html":
            if output_path is None:
                output_path = _timestamped_report_path("html", Path.cwd())
            if not isinstance(rendered, dict):
                raise RuntimeError(
                    "HTML report rendering did not return an asset bundle"
                )
            output_path = _write_html_report_output(output_path, rendered)
            print(f"Report written to {output_path}")
        elif output_path is not None:
            content = rendered if isinstance(rendered, bytes) else rendered + "\n"
            output_path = _write_report_output(output_path, content)
            print(f"Report written to {output_path}")
        elif isinstance(rendered, bytes):
            sys.stdout.buffer.write(rendered)
        else:
            print(rendered)
    finally:
        cache.close()
