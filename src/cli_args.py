from __future__ import annotations

"""Argument parser, source-loading, and apply-step helpers.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import argparse
import sys
from pathlib import Path

try:
    from . import __version__
    from .cache import default_cache_path
    from .cli_report import (
        REPORT_FORMAT_CHOICES,
        _default_report_format,
        _default_report_template,
        _env_value,
    )
    from ._parsers import VenvParser, find_venv
except ImportError:  # pragma: no cover
    from src import __version__
    from src.cache import default_cache_path
    from src.cli_report import (
        REPORT_FORMAT_CHOICES,
        _default_report_format,
        _default_report_template,
        _env_value,
    )
    from src._parsers import VenvParser, find_venv


def _build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="changes-ai",
        description=(
            "Evaluate the impact of updating software packages in a GitHub repository."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
    changes-ai --url https://github.com/owner/repo
    changes-ai --url https://github.com/owner/repo --libraries-io-key YOUR_KEY
    changes-ai --url https://github.com/owner/repo --chart
    changes-ai --source /path/to/project
    changes-ai --source /path/to/project --output table
    changes-ai scan --source /path/to/project --offline
    changes-ai cache list
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--url",
        metavar="URL",
        help="GitHub repository URL (e.g. https://github.com/owner/repo)",
    )
    input_group.add_argument(
        "--source",
        metavar="PATH",
        help=(
            "Path to a local project directory. Supported dependency manifests "
            "are used when present; otherwise '.venv' or 'venv' is auto-discovered. "
            "Defaults to CHANGES_AI_SOURCE_PATH from .env when set."
        ),
    )
    parser.add_argument(
        "--libraries-io-key",
        metavar="KEY",
        help=(
            "libraries.io API key (recommended to avoid rate limits). "
            "Falls back to the LIBRARIES_IO_API_KEY environment variable / .env file."
        ),
    )
    parser.add_argument(
        "--github-token",
        metavar="TOKEN",
        help="GitHub personal access token (for private repos / higher rate limits)",
    )
    parser.add_argument(
        "--repo-path",
        metavar="PATH",
        default=_env_value("CHANGES_AI_REPO_PATH"),
        help=(
            "Directory where --url repositories are cloned. Defaults to "
            "CHANGES_AI_REPO_PATH or ./repos."
        ),
    )
    parser.add_argument(
        "--cache-db",
        default=str(default_cache_path()),
        help=(
            "Path to the SQLite cache database. Defaults to CHANGES_AI_CACHE_DB "
            "from the environment / .env when set."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use only cached external API data and fail clearly when required data is missing.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Bypass cached external API data and refresh entries from upstream services.",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json", "both"],
        default="table",
        help="Version-mapping output format (default: table)",
    )
    parser.add_argument(
        "--format",
        choices=REPORT_FORMAT_CHOICES,
        default=_default_report_format("md"),
        help=(
            "Summary report output format when scan-generated reports are written. "
            "Defaults to CHANGES_AI_REPORT_FORMAT when set, otherwise md."
        ),
    )
    parser.add_argument(
        "--chart",
        action="store_true",
        help="Generate a dependency chart",
    )
    parser.add_argument(
        "--chart-format",
        choices=["mermaid", "ascii", "dot", "both"],
        default="ascii",
        help="Chart format when --chart is used (default: ascii)",
    )
    parser.add_argument(
        "--chart-output",
        metavar="FILE",
        default=_env_value("CHANGES_AI_CHART_OUTPUT"),
        help=(
            "Write the selected chart format to FILE instead of stdout. "
            "Relative paths are resolved under CHANGES_AI_REPORT_PATH when set."
        ),
    )
    parser.add_argument(
        "--transitive",
        action="store_true",
        help=(
            "Include transitive dependencies in the Mermaid chart "
            "(requires additional libraries.io API calls)"
        ),
    )
    parser.add_argument(
        "--report-output",
        metavar="DIR_OR_FILE",
        help=(
            "Write a summary report to a file or directory. Directory outputs "
            "use report_YYYYMMDD_HHMMSS.<format>; html reports create a folder "
            "containing index.html and style.css. Format defaults to "
            "CHANGES_AI_REPORT_FORMAT or md. When omitted, "
            "CHANGES_AI_REPORT_PATH is used as the report directory."
        ),
    )
    parser.add_argument(
        "--report-template",
        default=_default_report_template(),
        help=(
            "PDF report template name or path to a CSS file for scan-generated "
            "reports. Defaults to CHANGES_AI_REPORT_TEMPLATE when set, "
            "otherwise the built-in template."
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Run the full analysis suite: dependency chart, CVE scan, usage "
            "analysis, LLM impact analysis, and remediation planning."
        ),
    )
    parser.add_argument(
        "--cve-scan",
        action="store_true",
        help="Scan packages for known vulnerabilities via the OSV database",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        default="LOW",
        metavar="LEVEL",
        help=(
            "Only display CVEs at or above this severity level "
            "(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN, default: LOW)"
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        default=None,
        metavar="LEVEL",
        help=(
            "Exit with code 2 if any CVE at or above LEVEL is found "
            "(only meaningful with --cve-scan)"
        ),
    )
    parser.add_argument(
        "--usage-analysis",
        action="store_true",
        help="Analyse which symbols from each package the project's source actually uses (requires --source)",
    )
    parser.add_argument(
        "--impact-analysis",
        action="store_true",
        help=(
            "Run LLM-backed impact analysis for each vulnerable package (requires --cve-scan). "
            "Uses OPENAI_API_KEY and OPENAI_MODEL from environment / .env."
        ),
    )
    parser.add_argument(
        "--allow-commercial-usage-data",
        action="store_true",
        help=(
            "Allow source-derived usage-analysis data to be sent to known hosted "
            "commercial LLM endpoints. Can also be enabled with "
            "CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA=1."
        ),
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help=(
            "Run LLM-backed remediation planner and produce ranked upgrade paths "
            "(requires --impact-analysis). Uses OPENAI_API_KEY and OPENAI_MODEL."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "After the remediation plan is produced, open an interactive editor "
            "to review and apply a path. Requires --plan and --source. Skipped "
            "when stdin is not a TTY (use --auto-apply for non-interactive use)."
        ),
    )
    parser.add_argument(
        "--auto-apply",
        metavar="PATH_TYPE",
        choices=["minimum_breakage", "balanced", "maximum_coverage"],
        default=None,
        help=(
            "Non-interactively apply the named remediation path. Requires --plan "
            "and --source. Combine with --max-breakage-score to refuse "
            "application above a threshold."
        ),
    )
    parser.add_argument(
        "--max-breakage-score",
        type=float,
        metavar="SCORE",
        default=None,
        help=(
            "When --auto-apply is used, refuse to apply any path whose breakage "
            "score exceeds SCORE (0.0–1.0). Exit with code 3 if exceeded."
        ),
    )
    parser.add_argument(
        "--ecosystem",
        choices=["python", "npm"],
        default=None,
        help=(
            "Override automatic ecosystem detection. Useful for polyglot repos "
            "where both Python and NPM manifests are present."
        ),
    )
    return parser


def _load_source_packages(args, REGISTRY, detect_adapter, cloned_repo_locator):
    """Detect manifest, read packages, discover venv.

    Returns (packages, venv_pkgs, scan_locator, dependency_file_path,
             unused_packages, adapter, manifest_info).
    """
    scan_locator = ""
    dependency_file_path = "dependency-manifest"
    unused_packages: dict | None = None
    venv_pkgs: dict | None = None
    packages = None
    manifest_info = None
    adapter = None

    if args.source:
        source_path = Path(args.source)
        scan_locator = cloned_repo_locator or str(source_path.resolve())
        if args.ecosystem:
            adapter = REGISTRY[args.ecosystem]
            manifest_info = adapter.find_manifest(source_path)
            if manifest_info is None:
                print(
                    f"Error: --ecosystem {args.ecosystem} specified but no matching manifest found in {source_path}.",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            adapter = detect_adapter(source_path)
            if adapter is None:
                try:
                    find_venv(source_path)
                except FileNotFoundError:
                    print(
                        f"Error: no supported ecosystem detected in {source_path}. Supported: {', '.join(REGISTRY)}.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                adapter = REGISTRY["python"]
            manifest_info = adapter.find_manifest(source_path)

        if manifest_info is not None:
            try:
                rel_path = manifest_info.path.relative_to(source_path)
            except ValueError:
                rel_path = manifest_info.path
            print(f"Analysing source: {args.source} (dependency file: {rel_path})")
            dependency_file_path = str(rel_path)
            try:
                content = manifest_info.path.read_text(encoding="utf-8")
            except OSError as exc:
                print(f"Error reading {manifest_info.path}: {exc}", file=sys.stderr)
                sys.exit(1)
            packages = adapter.parse_manifest(content, manifest_info.file_type)
            if packages:
                venv_pkgs = adapter.discover_installed(source_path)
                if venv_pkgs is not None:
                    try:
                        venv_path = find_venv(source_path)
                        declared = {n.lower().replace("_", "-") for n in packages}
                        # Build transitive closure using venv METADATA dep graph so
                        # that indirect deps (e.g. certifi under requests) are not
                        # labelled as unused.
                        dep_graph = VenvParser.get_requires(venv_path)
                        transitive: set = set()
                        queue = list(declared)
                        while queue:
                            pkg = queue.pop()
                            for dep in dep_graph.get(pkg, []):
                                if dep not in transitive and dep not in declared:
                                    transitive.add(dep)
                                    queue.append(dep)
                        unused_packages = {
                            name: ver
                            for name, ver in venv_pkgs.items()
                            if name.lower().replace("_", "-") not in declared
                            and name.lower().replace("_", "-") not in transitive
                        }
                    except FileNotFoundError:
                        pass
            else:
                packages = None

        if packages is None:
            # No dependency file found — fall back to reading the venv directly.
            try:
                venv_path = find_venv(args.source)
            except FileNotFoundError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)
            print(f"Analysing source: {args.source} (venv: {venv_path})")
            dependency_file_path = str(venv_path)
            try:
                packages = adapter.discover_installed(source_path) if args.source else None
                venv_pkgs = packages
            except FileNotFoundError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)

    return packages, venv_pkgs, scan_locator, dependency_file_path, unused_packages, adapter, manifest_info


def _run_apply_step(
    args,
    adapter,
    manifest_info,
    remediation_paths,
    all_vulns,
    impact_reports,
    cache,
    run_id,
    source_path,
    cloned_repo_locator,
) -> None:
    """Handle --apply / --auto-apply after remediation planning."""
    try:
        from .apply import UpgradeSelection, apply_remediation
        from .remediation import _build_planning_context
        from .remediation_editor import EditorState, run_editor
    except ImportError:  # pragma: no cover
        from src.apply import UpgradeSelection, apply_remediation
        from src.remediation import _build_planning_context
        from src.remediation_editor import EditorState, run_editor

    if cloned_repo_locator is not None or not args.source:
        print(
            "Warning: --apply / --auto-apply requires --source (cannot modify a remote --url checkout). Skipping.",
            file=sys.stderr,
        )
        return
    if manifest_info is None:
        print(
            "Warning: no manifest found for apply step. Skipping.",
            file=sys.stderr,
        )
        return

    environment_root = None
    if adapter.name == "python":
        try:
            environment_root = find_venv(args.source)
        except FileNotFoundError:
            environment_root = None
    else:
        environment_root = source_path

    if args.auto_apply:
        target = next(
            (p for p in remediation_paths if p.path_type == args.auto_apply),
            None,
        )
        if target is None:
            print(
                f"Error: no remediation path of type '{args.auto_apply}' was generated.",
                file=sys.stderr,
            )
            cache.finish_run(run_id, status="failed")
            cache.close()
            sys.exit(1)

        if (
            args.max_breakage_score is not None
            and target.breakage_score > args.max_breakage_score
        ):
            print(
                f"Error: path '{args.auto_apply}' has breakage score "
                f"{target.breakage_score:.2f}, which exceeds "
                f"--max-breakage-score {args.max_breakage_score:.2f}. Not applying.",
                file=sys.stderr,
            )
            cache.finish_run(run_id, status="completed")
            cache.close()
            sys.exit(3)

        upgrades = [
            UpgradeSelection(
                package=u.package,
                from_version=u.from_version,
                to_version=u.to_version,
                fixes_cves=u.fixes_cves,
            )
            for u in target.upgrades
        ]
        result = apply_remediation(adapter, manifest_info, upgrades, environment_root)
        if not result.success:
            print(f"Error: apply failed: {result.error}", file=sys.stderr)
            cache.finish_run(run_id, status="failed")
            cache.close()
            sys.exit(1)
        print(f"Auto-applied '{args.auto_apply}' path successfully.")
    else:
        if not sys.stdin.isatty():
            print(
                "Note: --apply ignored in non-interactive mode. Use --auto-apply for CI use.",
                file=sys.stderr,
            )
        else:
            context = _build_planning_context(all_vulns, impact_reports)
            base = next(
                (p for p in remediation_paths if p.path_type == "balanced"),
                remediation_paths[0],
            )
            state = EditorState(
                all_paths=remediation_paths,
                all_impact_reports=impact_reports,
                all_vulns=all_vulns,
                selected_path_type=base.path_type,
                selection={
                    u.package.lower().replace("_", "-"): UpgradeSelection(
                        package=u.package,
                        from_version=u.from_version,
                        to_version=u.to_version,
                        fixes_cves=u.fixes_cves,
                    )
                    for u in base.upgrades
                },
                context=context,
            )
            run_editor(state, adapter, manifest_info, environment_root)
