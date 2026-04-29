from __future__ import annotations

"""CLI display helpers: tables, charts, summaries.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import os
import re
import sys

try:
    from .vulnerability import SEVERITY_RANK
    from ._clients import LibrariesIOClient, _concrete_version
except ImportError:  # pragma: no cover
    from src.vulnerability import SEVERITY_RANK
    from src._clients import LibrariesIOClient, _concrete_version


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

STATUS_SYMBOL = {
    "up-to-date": "✓",
    "outdated": "⚠",
    "unpinned": "?",
    "unknown": "-",
}


def print_version_table(mapping: list) -> None:
    """Print version mapping as a human-readable table."""
    if not mapping:
        print("No packages found.")
        return

    name_w = inst_w = req_w = lat_w = 0
    for m in mapping:
        name_w = max(name_w, len(m["name"]))
        inst_w = max(inst_w, len(m["installed"]))
        req_w = max(req_w, len(m["requirement"]))
        lat_w = max(lat_w, len(m["latest"]))
    name_w = max(name_w + 2, 9)
    inst_w = max(inst_w + 2, 19)
    req_w = max(req_w + 2, 13)
    lat_w = max(lat_w + 2, 16)

    header = (
        f"{'Package':<{name_w}} {'Installed Version':<{inst_w}}"
        f" {'Requirement':<{req_w}} {'Latest Version':<{lat_w}} Status"
    )
    print(header)
    print("-" * len(header))

    for m in mapping:
        symbol = STATUS_SYMBOL.get(m["status"], "-")
        print(
            f"{m['name']:<{name_w}} {m['installed']:<{inst_w}}"
            f" {m['requirement']:<{req_w}} {m['latest']:<{lat_w}} {symbol} {m['status']}"
        )


def generate_mermaid_chart(
    packages: dict,
    libraries_client: LibrariesIOClient,
    include_transitive: bool = False,
) -> str:
    """Return a Mermaid flowchart string for the dependency graph.

    Each direct dependency is shown as a node labelled ``name\\nversion``.
    When *include_transitive* is True, runtime sub-dependencies fetched from
    libraries.io are added as edges.
    """
    lines = ["graph TD"]

    def node_id(pkg_name: str) -> str:
        # Prefix all node IDs to avoid Mermaid keyword collisions (e.g. "style").
        return "pkg_" + re.sub(r"[^A-Za-z0-9]", "_", pkg_name)

    # Nodes for direct dependencies
    for name, version in packages.items():
        label = f"{name}\\n{version}" if version else name
        lines.append(f'    {node_id(name)}["{label}"]')

    if include_transitive:
        seen_nodes: set = set(node_id(n) for n in packages)
        seen_edges: set = set()
        edge_lines: list = []
        total = len(packages)
        for idx, (name, version) in enumerate(packages.items(), start=1):
            # Resolve a concrete version for the dep lookup: strip an exact ==pin,
            # otherwise ask libraries.io for the latest (specifiers are not valid here).
            resolved = _concrete_version(
                version
            ) or libraries_client.get_latest_version(name)
            if not resolved:
                continue
            print(
                f"\r  Fetching transitive deps for {name} ({idx}/{total})…\033[K",
                end="",
                file=sys.stderr,
            )
            deps = libraries_client.get_dependencies(name, resolved)
            parent = node_id(name)
            for dep in deps:
                child = node_id(dep)
                # Declare the child node only once
                if child not in seen_nodes:
                    seen_nodes.add(child)
                    lines.append(f'    {child}["{dep}"]')
                edge = (parent, child)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    edge_lines.append(f"    {parent} --> {child}")
        lines.extend(edge_lines)
        print("\r\033[K", end="", file=sys.stderr)

    return "\n".join(lines)


def generate_ascii_chart(
    packages: dict,
    libraries_client: "LibrariesIOClient | None" = None,
    include_transitive: bool = False,
) -> str:
    """Return an ASCII dependency tree.

    When *libraries_client* is supplied and *include_transitive* is True,
    runtime sub-dependencies are fetched and shown as child nodes.
    """
    if not packages:
        return "(no packages)"

    # Build children map: direct package → [dep, …]
    children: dict[str, list[str]] = {}
    if include_transitive and libraries_client is not None:
        total = len(packages)
        for idx, (name, version) in enumerate(packages.items(), start=1):
            # Resolve a concrete version for the dep lookup: strip an exact ==pin,
            # otherwise ask libraries.io for the latest (specifiers are not valid here).
            resolved = _concrete_version(
                version
            ) or libraries_client.get_latest_version(name)
            if not resolved:
                children[name] = []
                continue
            print(
                f"\r  Fetching transitive deps for {name} ({idx}/{total})…\033[K",
                end="",
                file=sys.stderr,
            )
            children[name] = libraries_client.get_dependencies(name, resolved)
        print("\r\033[K", end="", file=sys.stderr)
    else:
        children = {name: [] for name in packages}

    lines = []
    pkg_items = list(packages.items())
    for i, (name, version) in enumerate(pkg_items):
        is_last_pkg = i == len(pkg_items) - 1
        connector = "└─" if is_last_pkg else "├─"
        ver_str = f" ({version})" if version else ""
        lines.append(f"  {connector} {name}{ver_str}")

        deps = children.get(name, [])
        prefix = "     " if is_last_pkg else "  │  "
        for j, dep in enumerate(deps):
            is_last_dep = j == len(deps) - 1
            dep_connector = "└─" if is_last_dep else "├─"
            lines.append(f"{prefix}{dep_connector} {dep}")

    return "\n".join(lines)


def _print_usage_summary(report) -> None:
    """Print a concise usage-analysis summary table."""
    print("\n=== Usage Analysis ===\n")

    if not report.records and not report.unresolved:
        print("No package references found in source.")
        return

    # Group records by package
    by_pkg: dict = {}
    for r in report.records:
        by_pkg.setdefault(r.package, []).append(r)

    pkg_w = max((len(p) for p in by_pkg), default=7)
    sym_header = "Symbols used"
    header = f"{'Package':<{pkg_w}}  {sym_header}"
    print(header)
    print("-" * len(header))
    for pkg in sorted(by_pkg):
        symbols = sorted({r.symbol for r in by_pkg[pkg]})
        print(
            f"{pkg:<{pkg_w}}  {', '.join(symbols[:5])}"
            + (" …" if len(symbols) > 5 else "")
        )

    if report.unresolved:
        print("\n--- Unresolved / flagged ---")
        for u in report.unresolved:
            loc = f"{u.source_file}:{u.line}"
            pkg_label = f"[{u.package}] " if u.package else ""
            print(f"  {u.flag:<16}  {pkg_label}{loc}")


def _print_currency_summary(records: list[dict]) -> None:
    """Print a concise currency-signal summary table."""
    print("\n=== Currency Signals ===\n")

    if not records:
        print("No currency signals available.")
        return

    pkg_w = max(max(len(r["package"]) for r in records), len("Package"))
    date_w = max(
        max(len(str(r.get("latest_release_date") or "unknown")) for r in records),
        len("Latest Release"),
    )
    header = f"{'Package':<{pkg_w}}  {'Latest Release':<{date_w}}  Signals"
    print(header)
    print("-" * len(header))
    for record in records:
        signals = ", ".join(record.get("signals") or []) or "none"
        latest_release = record.get("latest_release_date") or "unknown"
        print(f"{record['package']:<{pkg_w}}  {latest_release:<{date_w}}  {signals}")


def _wrap(text: str, width: int, indent: str) -> str:
    """Wrap *text* to *width* columns, prefixing every line after the first with *indent*."""
    import textwrap

    lines = textwrap.wrap(text, width=width - len(indent))
    return f"\n{indent}".join(lines)


def _print_impact_summary(reports: list) -> None:
    """Print a human-readable impact analysis summary."""
    print("\n=== Impact Analysis ===\n")

    if not reports:
        print("No impact reports generated.")
        return

    BREAKAGE_SYMBOL = {"NONE": "✓", "LOW": "○", "MEDIUM": "⚠", "HIGH": "✖"}
    BREAKAGE_COLOR = {
        "NONE": "\033[0;32m",  # green
        "LOW": "\033[0;34m",  # blue
        "MEDIUM": "\033[0;33m",  # yellow
        "HIGH": "\033[1;31m",  # bold red
    }
    _RESET = "\033[0m"
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    # Column widths
    pkg_w = max(len(r.package) for r in reports)
    pkg_w = max(pkg_w + 2, 9)
    upg_w = max(len(f"{r.installed_version} → {r.candidate_version}") for r in reports)
    upg_w = max(upg_w + 2, 22)
    dlt_w = 7  # "major" is longest
    brk_w = 14  # "⚠ MEDIUM (0.50)" — padded for colour alignment
    con_w = 10  # "~ MEDIUM"

    header = (
        f"{'Package':<{pkg_w}} {'Upgrade':<{upg_w}} {'Delta':<{dlt_w}}"
        f" {'Breakage':<{brk_w}} {'Confidence':<{con_w}}"
    )
    print(header)
    print("-" * len(header))

    for r in reports:
        upgrade = f"{r.installed_version} → {r.candidate_version}"
        b_sym = BREAKAGE_SYMBOL.get(r.probable_breakage, "-")
        breakage_raw = f"{b_sym} {r.probable_breakage} ({r.breakage_score:.2f})"
        if use_color:
            color = BREAKAGE_COLOR.get(r.probable_breakage, "")
            breakage_col = f"{color}{breakage_raw:<{brk_w}}{_RESET}"
        else:
            breakage_col = f"{breakage_raw:<{brk_w}}"

        conf_sym = {"LOW": "?", "MEDIUM": "~", "HIGH": "✓"}.get(r.confidence, "?")
        conf_col = f"{conf_sym} {r.confidence}"
        fallback_note = " [fallback]" if r.fallback_used else ""

        print(
            f"{r.package:<{pkg_w}} {upgrade:<{upg_w}} {r.version_delta:<{dlt_w}}"
            f" {breakage_col} {conf_col}{fallback_note}"
        )

        # Detail lines — indented under the row
        indent = "  "
        wrap_width = 90

        if r.unresolved_usage:
            print(
                f"{indent}⚠ Unresolved usage (star/dynamic import) — assumed fully used"
            )

        if r.usage_intersection:
            syms = ", ".join(r.usage_intersection[:8])
            if len(r.usage_intersection) > 8:
                syms += " …"
            print(f"{indent}Used: {syms}")

        intersecting = [c for c in r.api_changes if c.intersects_usage]
        if intersecting:
            print(f"{indent}API changes affecting your usage:")
            bullet_indent = f"{indent}    "
            for c in intersecting:
                header_line = f"{indent}  • [{c.change_type}] {c.symbol}:"
                desc_wrapped = _wrap(c.description, wrap_width, bullet_indent)
                print(f"{header_line}\n{bullet_indent}{desc_wrapped}")

        if r.evidence:
            print(f"{indent}{_wrap(r.evidence, wrap_width, indent)}")

        for citation in getattr(r, "evidence_citations", []) or []:
            print(
                f"{indent}Source: {citation.source} - {citation.label} ({citation.url})"
            )

        print()


def _print_remediation_plan(paths: list, vulns: list) -> None:
    """Print a human-readable remediation plan summary."""
    print("\n=== Remediation Plan ===\n")

    if not paths:
        print("No remediation paths generated.")
        return

    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    _RESET = "\033[0m"
    CONF_COLOR = {
        "HIGH": "\033[0;32m",  # green
        "MEDIUM": "\033[0;33m",  # yellow
        "LOW": "\033[0;34m",  # blue
    }
    PATH_LABEL = {
        "minimum_breakage": "Minimum Breakage",
        "maximum_coverage": "Maximum Coverage",
        "balanced": "Balanced",
    }

    # Collect all CVE IDs across all paths so we can summarise in the headline.
    all_cve_ids: set = set()
    for v in vulns:
        all_cve_ids.add(v.cve_id)
    total_cves = len(all_cve_ids)

    # One-line headline summarising what each path resolves.
    headline_parts = []
    for p in paths:
        label = PATH_LABEL.get(p.path_type, p.path_type)
        resolved = len(p.cves_resolved)
        headline_parts.append(f"{label.lower()} {resolved}/{total_cves}")
    if headline_parts:
        print(f"{len(paths)} path(s) generated: {' · '.join(headline_parts)}.\n")

    wrap_width = 90
    indent = "  "

    for p in paths:
        label = PATH_LABEL.get(p.path_type, p.path_type)
        conf_sym = {"LOW": "?", "MEDIUM": "~", "HIGH": "✓"}.get(p.confidence, "?")

        if use_color:
            color = CONF_COLOR.get(p.confidence, "")
            conf_str = f"{color}{conf_sym} {p.confidence}{_RESET}"
        else:
            conf_str = f"{conf_sym} {p.confidence}"

        fallback_note = " [fallback]" if p.fallback_used else ""
        print(f"[{label}]{fallback_note}")

        # Rationale (immediately under the title)
        if p.rationale:
            print(f"{indent}{_wrap(p.rationale, wrap_width, indent)}")
            print()

        print(
            f"{indent}Exposure: {p.exposure_score:.2f}  "
            f"Breakage: {p.breakage_score:.2f}  "
            f"Confidence: {conf_str}"
        )

        # Upgrades
        if p.upgrades:
            for u in p.upgrades:
                cve_note = (
                    f"  (fixes {', '.join(u.fixes_cves)})" if u.fixes_cves else ""
                )
                print(
                    f"{indent}↑  {u.package}  {u.from_version} → {u.to_version}{cve_note}"
                )
        else:
            print(f"{indent}(no upgrades)")

        # CVE resolution summary
        if p.cves_resolved:
            print(f"{indent}Resolves:   {', '.join(sorted(p.cves_resolved))}")
        if p.cves_unresolved:
            print(f"{indent}Open:       {', '.join(sorted(p.cves_unresolved))}")
        if p.cves_no_fix:
            print(f"{indent}No fix:     {', '.join(sorted(p.cves_no_fix))}")

        print()

    # No-fix callout (shown once, below all paths).
    no_fix_cves: set = set()
    for p in paths:
        no_fix_cves.update(p.cves_no_fix)
    if no_fix_cves:
        # Build a severity lookup for display.
        sev_lookup: dict = {}
        for v in vulns:
            sev_lookup[v.cve_id] = v.severity
        print("=== No Fix Available ===\n")
        for cve_id in sorted(no_fix_cves):
            sev = sev_lookup.get(cve_id, "UNKNOWN")
            # Find the package name.
            pkg = next((v.package for v in vulns if v.cve_id == cve_id), "unknown")
            print(
                f"  ⚠ {cve_id} ({sev}) in {pkg} — no fix version known. "
                "Consider replacing, pinning below the affected range, or accepting the risk."
            )
        print()


def _print_cache_entries(cache) -> None:
    entries = cache.list_entries()
    if not entries:
        print("Cache is empty.")
        return

    source_w = max(max(len(e.source) for e in entries), len("Source"))
    key_w = max(max(len(e.cache_key) for e in entries), len("Key"))
    header = f"{'Source':<{source_w}}  {'Key':<{key_w}}  Expires"
    print(header)
    print("-" * len(header))
    for entry in entries:
        print(
            f"{entry.source:<{source_w}}  {entry.cache_key:<{key_w}}  {entry.expires_at}"
        )
