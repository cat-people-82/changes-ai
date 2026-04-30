#!/usr/bin/env python3
"""
Changes AI: AI-powered CVE impact analysis and remediation planner.

Supports local and remote source scanning for Python and NPM projects.
Performs CVE scanning via OSV, AST-based usage analysis, LLM-backed impact
and remediation analysis, multi-format reports (md, html, pdf, sarif, dot,
json), and interactive or non-interactive remediation apply.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from dotenv import load_dotenv

try:
    from . import __version__
    from .cache import CacheMissError, SQLiteCache, default_cache_path
    from .cli_commands import _run_cache_command, _run_report_command
    from .cli_args import _build_argument_parser, _load_source_packages, _run_apply_step
    from .cli_display import (
        STATUS_SYMBOL,
        _print_cache_entries,
        _print_currency_summary,
        _print_impact_summary,
        _print_remediation_plan,
        _print_usage_summary,
        _wrap,
        generate_ascii_chart,
        generate_mermaid_chart,
        print_version_table,
    )
    from .cli_report import (
        REPORT_FORMAT_CHOICES,
        REPORT_FORMAT_EXTENSIONS,
        _default_report_format,
        _default_report_template,
        _env_value,
        _render_cached_report,
        _resolve_output_path,
        _resolve_report_output_path,
        _timestamped_report_path,
        _write_html_report_output,
        _write_report_output,
        _write_text_output,
    )
    from ._clients import (
        LibrariesIOClient,
        _build_mapping_from_currency_records,
        _concrete_version,
        _fingerprint_payload,
        build_version_mapping,
    )
    from ._parsers import (
        DEPENDENCY_CANDIDATES,
        DependencyParser,
        VenvParser,
        _load_yaml_module,
        find_venv,
    )
    from .currency import analyse_currency
    from .executive_summary import (
        _executive_summary_api_key,
        _generate_executive_summary_narrative,
    )
    from .graph import render_dot_graph
    from .impact import LLMClient, run_impact_analysis, usage_data_requires_opt_in
    from .remediation import run_remediation_plan
    from .reporting import (
        render_dot_report,
        render_html_report_bundle,
        render_json_report,
        render_markdown_report,
        render_pdf_report,
        render_sarif_report,
    )
    from .vulnerability import (
        SEVERITY_RANK,
        print_cve_table,
        scan_vulnerabilities,
    )
except ImportError:  # pragma: no cover - direct script execution path
    from src import __version__
    from src.cache import CacheMissError, SQLiteCache, default_cache_path
    from src.cli_commands import _run_cache_command, _run_report_command
    from src.cli_args import _build_argument_parser, _load_source_packages, _run_apply_step
    from src.cli_display import (
        STATUS_SYMBOL,
        _print_cache_entries,
        _print_currency_summary,
        _print_impact_summary,
        _print_remediation_plan,
        _print_usage_summary,
        _wrap,
        generate_ascii_chart,
        generate_mermaid_chart,
        print_version_table,
    )
    from src.cli_report import (
        REPORT_FORMAT_CHOICES,
        REPORT_FORMAT_EXTENSIONS,
        _default_report_format,
        _default_report_template,
        _env_value,
        _render_cached_report,
        _resolve_output_path,
        _resolve_report_output_path,
        _timestamped_report_path,
        _write_html_report_output,
        _write_report_output,
        _write_text_output,
    )
    from src._clients import (
        LibrariesIOClient,
        _build_mapping_from_currency_records,
        _concrete_version,
        _fingerprint_payload,
        build_version_mapping,
    )
    from src._parsers import (
        DEPENDENCY_CANDIDATES,
        DependencyParser,
        VenvParser,
        _load_yaml_module,
        find_venv,
    )
    from src.currency import analyse_currency
    from src.executive_summary import (
        _executive_summary_api_key,
        _generate_executive_summary_narrative,
    )
    from src.graph import render_dot_graph
    from src.impact import LLMClient, run_impact_analysis, usage_data_requires_opt_in
    from src.remediation import run_remediation_plan
    from src.reporting import (
        render_dot_report,
        render_html_report_bundle,
        render_json_report,
        render_markdown_report,
        render_pdf_report,
        render_sarif_report,
    )
    from src.vulnerability import (
        SEVERITY_RANK,
        print_cve_table,
        scan_vulnerabilities,
    )


# Re-exports required by tests/test_smoke.py and ecosystem/python_adapter.py
# noqa: F401 — imported for re-export
__all__ = [
    "DEPENDENCY_CANDIDATES",
    "DependencyParser",
    "LibrariesIOClient",
    "VenvParser",
    "find_venv",
    "_build_graph_packages",
    "_build_cve_scan_packages",
    "_executive_summary_api_key",
    "_format_skipped_cve_packages",
    "parse_github_url",
]


# ---------------------------------------------------------------------------
# Repository and dependency discovery
# ---------------------------------------------------------------------------


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL.

    Accepts URLs such as:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        github.com/owner/repo
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    pattern = r"(?:https?://)?github\.com/([^/]+)/([^/]+)$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(
            f"Invalid GitHub URL: {url!r}. "
            "Expected format: https://github.com/owner/repo"
        )
    return match.group(1), match.group(2)


def _repo_base_path(path: str | None = None) -> Path:
    value = path or _env_value("CHANGES_AI_REPO_PATH")
    return Path(value or "./repos").expanduser()


def _clone_auth_env(github_token: str | None, askpass_path: Path | None = None) -> dict:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if github_token and askpass_path is not None:
        askpass_path.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "*Username*) printf '%s\\n' x-access-token ;;\n"
            "*Password*) printf '%s\\n' \"$CHANGES_AI_GIT_TOKEN\" ;;\n"
            "*) printf '\\n' ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        askpass_path.chmod(0o700)
        env["GIT_ASKPASS"] = str(askpass_path)
        env["CHANGES_AI_GIT_TOKEN"] = github_token
    return env


def clone_github_repo(
    owner: str,
    repo: str,
    repo_base_path: str | Path | None = None,
    github_token: str | None = None,
) -> Path:
    """Clone a GitHub repository under *repo_base_path* and return its path."""
    base_path = _repo_base_path(str(repo_base_path) if repo_base_path else None)
    checkout_path = base_path / owner / repo

    if checkout_path.exists():
        if (checkout_path / ".git").is_dir():
            print(f"Using existing clone: {checkout_path}")
            return checkout_path
        if any(checkout_path.iterdir()):
            raise FileExistsError(
                f"Clone destination already exists and is not a Git repository: {checkout_path}"
            )

    checkout_path.parent.mkdir(parents=True, exist_ok=True)
    clone_url = f"https://github.com/{owner}/{repo}.git"
    print(f"Cloning repository to {checkout_path}…")

    with tempfile.TemporaryDirectory(prefix="changes-ai-git-askpass-") as tmpdir:
        askpass_path = Path(tmpdir) / "askpass.sh" if github_token else None
        env = _clone_auth_env(github_token, askpass_path)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, str(checkout_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "git clone failed").strip()
        raise RuntimeError(message)

    return checkout_path


# ---------------------------------------------------------------------------
# CVE / graph package helpers
# ---------------------------------------------------------------------------


def _build_cve_scan_packages(
    packages: dict,
    venv_pkgs: dict | None,
) -> tuple[dict, list[tuple[str, str | None]]]:
    skipped: list[tuple[str, str | None]] = []

    if venv_pkgs:
        _norm = lambda n: n.lower().replace("_", "-")
        venv_index = {_norm(k): v for k, v in venv_pkgs.items()}
        scan_packages = {}
        for name, requirement in packages.items():
            installed_version = venv_index.get(_norm(name))
            concrete_version = installed_version or _concrete_version(requirement)
            if concrete_version:
                scan_packages[name] = concrete_version
            else:
                skipped.append((name, requirement))

        scan_norm = {_norm(k) for k in scan_packages}
        for name, version in venv_pkgs.items():
            norm_name = _norm(name)
            if norm_name not in scan_norm:
                scan_packages[name] = version
                scan_norm.add(norm_name)
        return scan_packages, skipped

    scan_packages = {}
    for name, requirement in packages.items():
        concrete_version = _concrete_version(requirement)
        if concrete_version:
            scan_packages[name] = concrete_version
        else:
            skipped.append((name, requirement))
    return scan_packages, skipped


def _build_graph_packages(
    packages: dict,
    venv_pkgs: dict | None,
    *,
    include_installed: bool,
) -> dict:
    """Return the package set used to construct cached dependency edges.

    By default this is the declared manifest package set. When
    ``include_installed`` is true, any additional packages discovered in
    the local virtualenv are included as direct project dependencies too.

    This keeps the report graph aligned with the package universe used by
    CVE scanning, which can include installed-but-undeclared packages.
    Declared manifest entries win over venv-discovered versions so we do
    not discard the user's original requirement metadata.
    """
    graph_packages = dict(packages)
    if include_installed and venv_pkgs:
        for name, version in venv_pkgs.items():
            graph_packages.setdefault(name, version)
    return graph_packages


def _format_skipped_cve_packages(skipped: list[tuple[str, str | None]]) -> str:
    if not skipped:
        return ""
    preview = ", ".join(
        f"{name} ({requirement or 'unpinned'})" for name, requirement in skipped[:8]
    )
    if len(skipped) > 8:
        preview += f", ... {len(skipped) - 8} more"
    return (
        "Warning: CVE scan skipped "
        f"{len(skipped)} package(s) without a concrete installed version. "
        "Use exact pins, a lockfile, or scan a project with a local virtual "
        f"environment to avoid false negatives: {preview}"
    )


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def main() -> None:
    try:
        from .ecosystem import REGISTRY, detect_adapter
    except ImportError:  # pragma: no cover - direct script execution path
        from src.ecosystem import REGISTRY, detect_adapter

    # Load .env file (if present) before parsing arguments so that
    # LIBRARIES_IO_API_KEY and other variables are available via os.environ.
    load_dotenv()

    raw_argv = sys.argv[1:]
    if raw_argv and raw_argv[0] == "cache":
        _run_cache_command(raw_argv[1:])
        return
    if raw_argv and raw_argv[0] == "report":
        _run_report_command(raw_argv[1:])
        return
    if raw_argv and raw_argv[0] == "scan":
        sys.argv = [sys.argv[0]] + raw_argv[1:]
    elif raw_argv and raw_argv[0] == "graph":
        sys.argv = [sys.argv[0]] + raw_argv[1:] + ["--chart"]
    elif raw_argv and raw_argv[0] == "cves":
        sys.argv = [sys.argv[0]] + raw_argv[1:] + ["--cve-scan"]
    elif raw_argv and raw_argv[0] == "usage":
        sys.argv = [sys.argv[0]] + raw_argv[1:] + ["--usage-analysis"]
    elif raw_argv and raw_argv[0] == "plan":
        sys.argv = (
            [sys.argv[0]] + raw_argv[1:] + ["--cve-scan", "--impact-analysis", "--plan"]
        )

    parser = _build_argument_parser()
    args = parser.parse_args()

    if not args.url and not args.source:
        args.source = _env_value("CHANGES_AI_SOURCE_PATH")

    if args.all:
        args.chart = True
        args.cve_scan = True
        args.usage_analysis = True
        args.impact_analysis = True
        args.plan = True

    if args.offline and args.refresh:
        print(
            "Error: --offline and --refresh cannot be used together.", file=sys.stderr
        )
        sys.exit(1)

    # No arguments → print help and exit cleanly
    if (args.apply or args.auto_apply) and not args.url and not args.source:
        print(
            "Warning: --apply / --auto-apply requires --source (cannot modify a remote --url checkout). Skipping.",
            file=sys.stderr,
        )
        sys.exit(0)
    if not args.url and not args.source:
        parser.print_help()
        sys.exit(0)

    # Resolve keys: CLI flag > environment variable (.env or shell).
    libraries_io_key = args.libraries_io_key or os.environ.get("LIBRARIES_IO_API_KEY")
    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")

    cloned_repo_locator = None
    if args.url:
        try:
            owner, repo = parse_github_url(args.url)
            clone_path = clone_github_repo(
                owner,
                repo,
                repo_base_path=args.repo_path,
                github_token=github_token,
            )
        except (ValueError, FileExistsError, RuntimeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        args.source = str(clone_path)
        cloned_repo_locator = f"github:{owner}/{repo}"

    packages, venv_pkgs, scan_locator, dependency_file_path, unused_packages, adapter, manifest_info = (
        _load_source_packages(args, REGISTRY, detect_adapter, cloned_repo_locator)
    )
    source_path = Path(args.source) if args.source else None

    if not packages:
        print("No packages found.")
        sys.exit(0)

    print(f"Packages detected: {len(packages)}")

    # --- Fetch version info from libraries.io ----------------------------
    cache = SQLiteCache(args.cache_db)
    libraries_client = LibrariesIOClient(
        api_key=libraries_io_key,
        cache=cache,
        refresh=args.refresh,
        offline=args.offline,
    )
    if not libraries_io_key:
        print(
            "Note: No libraries.io API key found (--libraries-io-key or "
            "LIBRARIES_IO_API_KEY in .env). "
            "Unauthenticated requests are rate-limited (~60/min)."
        )

    run_id = cache.start_run(
        locator=scan_locator,
        source_fingerprint={
            "packages": packages,
            "dependency_file": dependency_file_path,
        },
        run_fingerprint=_fingerprint_payload(
            {
                "packages": packages,
                "source": scan_locator,
                "dependency_file": dependency_file_path,
                "flags": {
                    "cve_scan": args.cve_scan,
                    "usage_analysis": args.usage_analysis,
                    "impact_analysis": args.impact_analysis,
                    "plan": args.plan,
                },
            }
        ),
    )

    print("Fetching version information…")
    try:
        if adapter.name == "python":
            mapping = build_version_mapping(packages, libraries_client, venv_pkgs)
            currency_records = analyse_currency(mapping, libraries_client)
        else:
            adapter_currency = adapter.fetch_currency(list(packages.keys()), cache)
            mapping = _build_mapping_from_currency_records(
                packages,
                adapter_currency,
                venv_pkgs,
            )
            currency_records = []
            for record in adapter_currency:
                payload = dict(record.__dict__)
                payload["is_deprecated"] = payload.get("deprecated", False)
                currency_records.append(payload)
    except CacheMissError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
        cache.close()
        sys.exit(1)
    cache.store_packages(run_id, mapping)
    cache.store_currency_records(run_id, currency_records)

    project_graph_name = (
        Path(scan_locator).name if args.source else scan_locator.replace("github:", "")
    )
    graph_packages = _build_graph_packages(
        packages,
        venv_pkgs,
        include_installed=args.cve_scan,
    )
    graph_edges = adapter.build_graph(
        graph_packages,
        venv_pkgs,
        libraries_client,
        include_transitive=args.transitive,
    )
    graph_edges = [
        {"parent": edge["parent"], "child": edge["child"]}
        if isinstance(edge, dict)
        else {"parent": edge.parent, "child": edge.child}
        for edge in graph_edges
    ]
    for edge in graph_edges:
        if edge["parent"] == "project":
            edge["parent"] = project_graph_name or "project"
    cache.store_dependency_edges(run_id, graph_edges)

    # --- Version mapping output ------------------------------------------
    if args.output in ("table", "both"):
        print("\n=== Version Mapping ===\n")
        print_version_table(mapping)

    if args.output in ("json", "both"):
        print("\n=== JSON Output ===\n")
        print(json.dumps(mapping, indent=2))

    # --- Dependency chart ------------------------------------------------
    if args.chart:
        if args.chart_format in ("ascii", "both"):
            try:
                ascii_chart = generate_ascii_chart(
                    packages,
                    libraries_client=libraries_client,
                    include_transitive=args.transitive,
                )
            except CacheMissError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
                cache.close()
                sys.exit(1)
            if args.chart_output and args.chart_format == "ascii":
                output_path = _write_text_output(
                    _resolve_output_path(args.chart_output), ascii_chart + "\n"
                )
                print(f"ASCII chart written to {output_path}")
            else:
                print("\n=== Dependency Chart (ASCII) ===\n")
                print(ascii_chart)

        if args.chart_format == "dot":
            dot_graph = render_dot_graph(
                graph_edges,
                graph_name=project_graph_name or "project",
            )
            if args.chart_output:
                output_path = _write_text_output(
                    _resolve_output_path(args.chart_output), dot_graph + "\n"
                )
                print(f"DOT graph written to {output_path}")
            else:
                print("\n=== Dependency Chart (DOT) ===\n")
                print(dot_graph)

        if args.chart_format in ("mermaid", "both"):
            print("\nGenerating Mermaid chart…")
            try:
                mermaid = generate_mermaid_chart(
                    packages,
                    libraries_client,
                    include_transitive=args.transitive,
                )
            except CacheMissError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
                cache.close()
                sys.exit(1)
            if args.chart_output:
                mermaid = "```mermaid\n" + mermaid + "\n```\n"
                output_path = _write_text_output(
                    _resolve_output_path(args.chart_output), mermaid + "\n"
                )
                print(f"Mermaid chart written to {output_path}")
            else:
                print("\n=== Dependency Chart (Mermaid) ===\n")
                print(mermaid)

    # --- Unused packages -------------------------------------------------
    if unused_packages is not None:
        print("\n=== Unused Packages ===\n")
        if unused_packages:
            for pkg_name, pkg_ver in sorted(
                unused_packages.items(), key=lambda x: x[0].lower()
            ):
                print(f"  - {pkg_name} {pkg_ver}")
        else:
            print("  None")

    # --- Summary ---------------------------------------------------------
    counts = {}
    for m in mapping:
        counts[m["status"]] = counts.get(m["status"], 0) + 1

    print("\n=== Summary ===")
    label_w = 15  # width for the left-hand label column
    print(f"{'Total packages':<{label_w}}: {len(mapping)}")
    print(f"{'Up-to-date':<{label_w}}: {counts.get('up-to-date', 0)}")
    print(f"{'Outdated':<{label_w}}: {counts.get('outdated', 0)}")
    print(f"{'Unpinned':<{label_w}}: {counts.get('unpinned', 0)}")
    print(f"{'Unknown':<{label_w}}: {counts.get('unknown', 0)}")
    if unused_packages is not None:
        print(f"{'Unused':<{label_w}}: {len(unused_packages)}")
    else:
        print(f"{'Unused':<{label_w}}: N/A")

    _print_currency_summary(currency_records)

    # --- CVE scan --------------------------------------------------------
    all_vulns: list = []
    if args.cve_scan:
        print("\nScanning for vulnerabilities via OSV…")
        # Build the scan set from declared packages + anything else installed in
        # the venv (unused packages), using concrete installed versions throughout.
        scan_packages, skipped_cve_packages = _build_cve_scan_packages(
            packages, venv_pkgs
        )
        skipped_warning = _format_skipped_cve_packages(skipped_cve_packages)
        if skipped_warning:
            print(skipped_warning, file=sys.stderr)
        try:
            all_vulns = scan_vulnerabilities(
                scan_packages,
                cache=cache,
                refresh=args.refresh,
                offline=args.offline,
                ecosystem=adapter.osv_ecosystem,
            )
        except CacheMissError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
            cache.close()
            sys.exit(1)
        cache.store_vulnerabilities(run_id, all_vulns)

        threshold_rank = SEVERITY_RANK.get(args.severity_threshold, 0)
        visible_vulns = [
            v for v in all_vulns if SEVERITY_RANK.get(v.severity, 0) >= threshold_rank
        ]

        print(f"\n=== CVE Scan ({args.severity_threshold}+) ===\n")
        print_cve_table(visible_vulns)

    # --- Usage analysis --------------------------------------------------
    usage_report = None
    remediation_paths: list = []
    if args.usage_analysis:
        if args.source:
            print("\nAnalysing source usage…")
            usage_report = adapter.analyse_usage(source_path, packages)
            _print_usage_summary(usage_report)
            cache.store_usage_report(run_id, usage_report)
        else:
            print(
                "Note: usage analysis requires a local source directory (--source). "
                "Skipping.",
                file=sys.stderr,
            )

    # --- Impact analysis -------------------------------------------------
    impact_reports: list = []
    if args.impact_analysis:
        if not args.cve_scan:
            print(
                "Note: --impact-analysis requires --cve-scan. Skipping.",
                file=sys.stderr,
            )
        else:
            openai_key = os.environ.get("OPENAI_API_KEY")
            openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
            openai_base = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
            allow_commercial_usage_data = (
                args.allow_commercial_usage_data
                or os.environ.get("CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA", "").lower()
                in {"1", "true", "yes"}
            )
            if not openai_key:
                print(
                    "Error: --impact-analysis requires OPENAI_API_KEY in environment or .env.",
                    file=sys.stderr,
                )
                cache.finish_run(
                    run_id,
                    status="failed",
                    invalidation_reason="missing OPENAI_API_KEY",
                )
                cache.close()
                sys.exit(1)
            elif (
                usage_data_requires_opt_in(openai_base, usage_report)
                and not allow_commercial_usage_data
            ):
                print(
                    "Error: refusing to send source-derived usage-analysis data to a "
                    "hosted commercial LLM endpoint without explicit opt-in. Re-run "
                    "with --allow-commercial-usage-data or set "
                    "CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA=1.",
                    file=sys.stderr,
                )
                cache.finish_run(
                    run_id,
                    status="failed",
                    invalidation_reason="commercial usage-data opt-in required",
                )
                cache.close()
                sys.exit(1)
            else:
                if not args.usage_analysis:
                    print(
                        "Warning: --usage-analysis not enabled; impact assessment will run "
                        "without usage intersection, which reduces confidence. "
                        "Re-run with --usage-analysis for a better result.",
                        file=sys.stderr,
                    )
                print("\nRunning LLM impact analysis…")
                try:
                    impact_reports = run_impact_analysis(
                        vulns=all_vulns,
                        usage_report=usage_report,
                        api_key=openai_key,
                        model=openai_model,
                        api_base=openai_base,
                        allow_commercial_usage_data=allow_commercial_usage_data,
                        currency_records=currency_records,
                        github_token=github_token,
                        cache=cache,
                        refresh=args.refresh,
                        offline=args.offline,
                    )
                except CacheMissError as exc:
                    print(f"Error: {exc}", file=sys.stderr)
                    cache.finish_run(
                        run_id, status="failed", invalidation_reason=str(exc)
                    )
                    cache.close()
                    sys.exit(1)
                _print_impact_summary(impact_reports)
                cache.store_impact_reports(run_id, impact_reports)
                if args.output in ("json", "both"):
                    print("\n=== Impact Analysis (JSON) ===\n")
                    print(json.dumps([r.to_dict() for r in impact_reports], indent=2))

    # --- Remediation plan ------------------------------------------------
    if args.plan:
        if not args.impact_analysis:
            print(
                "Error: --plan requires --impact-analysis (no breakage signal available without it).",
                file=sys.stderr,
            )
            cache.finish_run(
                run_id,
                status="failed",
                invalidation_reason="--plan without --impact-analysis",
            )
            cache.close()
            sys.exit(1)
        elif not args.cve_scan:
            # impact_analysis already requires cve_scan, but guard defensively.
            print(
                "Error: --plan requires --cve-scan.",
                file=sys.stderr,
            )
            cache.finish_run(
                run_id, status="failed", invalidation_reason="--plan without --cve-scan"
            )
            cache.close()
            sys.exit(1)
        else:
            # openai_key/model/base are already resolved and validated by the
            # --impact-analysis block above (which --plan requires).
            print("\nRunning remediation planner…")
            try:
                remediation_paths = run_remediation_plan(
                    vulns=all_vulns,
                    impact_reports=impact_reports,
                    api_key=openai_key,
                    model=openai_model,
                    api_base=openai_base,
                    currency_records=currency_records,
                    cache=cache,
                    refresh=args.refresh,
                    offline=args.offline,
                )
            except CacheMissError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
                cache.close()
                sys.exit(1)
            _print_remediation_plan(remediation_paths, all_vulns)
            cache.store_remediation_paths(run_id, remediation_paths)
            if args.output in ("json", "both"):
                print("\n=== Remediation Plan (JSON) ===\n")
                print(
                    json.dumps(
                        {
                            "remediation_plan": {
                                "paths": [p.to_dict() for p in remediation_paths]
                            }
                        },
                        indent=2,
                    )
                )

    if (args.apply or args.auto_apply) and remediation_paths:
        _run_apply_step(
            args,
            adapter,
            manifest_info,
            remediation_paths,
            all_vulns,
            impact_reports,
            cache,
            run_id,
            source_path if args.source else None,
            cloned_repo_locator,
        )

    report = cache.get_run_report(run_id)
    if report is not None:
        executive_summary_narrative = _generate_executive_summary_narrative(
            report,
            api_key=_executive_summary_api_key(args.impact_analysis),
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            api_base=os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1"),
            cache=cache,
            refresh=args.refresh,
            offline=args.offline,
        )
        cache.store_run_summary(run_id, executive_summary_narrative)

    scan_report_format = args.format
    report_output_path = _resolve_report_output_path(
        scan_report_format, args.report_output
    )
    if report_output_path is not None:
        report = cache.get_run_report(run_id)
        if report is not None:
            rendered = _render_cached_report(
                report,
                scan_report_format,
                run_id,
                report_template=args.report_template,
            )
            if scan_report_format == "html":
                if not isinstance(rendered, dict):
                    raise RuntimeError(
                        "HTML report rendering did not return an asset bundle"
                    )
                output_path = _write_html_report_output(report_output_path, rendered)
            else:
                content = rendered if isinstance(rendered, bytes) else rendered + "\n"
                output_path = _write_report_output(report_output_path, content)
            print(f"\nReport written to {output_path}")

    # --- Deferred --fail-on exit (after all analysis is complete) --------
    if args.cve_scan and args.fail_on is not None:
        fail_rank = SEVERITY_RANK.get(args.fail_on, 0)
        failing = [
            v for v in all_vulns if SEVERITY_RANK.get(v.severity, 0) >= fail_rank
        ]
        if failing:
            print(
                f"\nFailing: {len(failing)} vulnerability/ies at or above {args.fail_on}.",
                file=sys.stderr,
            )
            cache.finish_run(run_id, status="completed")
            cache.close()
            sys.exit(2)

    cache.finish_run(run_id)
    cache.close()


if __name__ == "__main__":
    main()
