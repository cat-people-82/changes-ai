"""Report renderers for cached Changes AI runs."""

from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from .graph import (
    build_package_states,
    render_dot_graph,
    render_svg_graph,
)
from .render_report import render_report_html_bundle, render_report_pdf

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "none",
}
SARIF_SECURITY_SEVERITY = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "4.0",
    "LOW": "0.1",
}
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability/{vuln_id}"
EXTERNAL_LINK_ICON_PATH = (
    Path(__file__).resolve().parent.parent / "images" / "external-link.svg"
)


def _load_external_link_icon_data_uri() -> str:
    """Return the bundled external-link SVG as a data URI."""
    try:
        svg_markup = EXTERNAL_LINK_ICON_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return f"data:image/svg+xml;utf8,{quote(svg_markup)}"


_EXTERNAL_LINK_ICON_DATA_URI_CACHE: str | None = None


def _get_external_link_icon_data_uri() -> str:
    global _EXTERNAL_LINK_ICON_DATA_URI_CACHE
    if _EXTERNAL_LINK_ICON_DATA_URI_CACHE is None:
        _EXTERNAL_LINK_ICON_DATA_URI_CACHE = _load_external_link_icon_data_uri()
    return _EXTERNAL_LINK_ICON_DATA_URI_CACHE


# Keep the module-level name for backward compatibility but populate lazily on first use.
def __getattr__(name: str):
    if name == "EXTERNAL_LINK_ICON_DATA_URI":
        return _get_external_link_icon_data_uri()
    raise AttributeError(name)


def render_json_report(report: dict) -> str:
    return json.dumps(report, indent=2)


def _group_by(items: list[dict], key: str) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for item in items:
        grouped.setdefault(str(item.get(key) or "UNKNOWN"), []).append(item)
    return grouped


def _render_osv_link(vuln_id: str) -> str:
    """Render a report-safe HTML link to the OSV vulnerability page."""
    safe_vuln_id = html.escape(vuln_id, quote=True)
    return (
        f'<a class="osv-link" href="{OSV_VULNERABILITY_URL.format(vuln_id=safe_vuln_id)}" '
        f'target="_blank" rel="noopener noreferrer" '
        f'title="Open {safe_vuln_id} on osv.dev in a new tab">'
        f'{safe_vuln_id}<img class="external-link-icon" src="{_get_external_link_icon_data_uri()}" '
        f'alt="" aria-hidden="true"></a>'
    )


def _report_dependency_graph_states(report: dict) -> dict[str, str]:
    """Return report-graph package states.

    HTML/PDF reports keep the pre-remediation severity view so vulnerable
    packages remain colour-coded by severity in the dependency graph.
    ``no_fix`` markers are preserved, but upgrade-path styling is not
    applied in this view.
    """
    return build_package_states(report, include_upgrades=False)


def _report_dependency_graph_focus(report: dict) -> set[str]:
    """Return the package names that should drive the report graph.

    Prefer the packages surfaced in the Impact Summary. When there are no
    impact reports, fall back to the packages that carry vulnerability
    state in the report.
    """
    impacts = report.get("impact_reports") or []
    focus = {
        str(item.get("package") or "")
        for item in impacts
        if str(item.get("package") or "").strip()
    }
    if focus:
        return focus
    return set(_report_dependency_graph_states(report))


def _filter_report_graph_edges(
    edges: list[dict], focus_packages: set[str]
) -> list[dict]:
    """Keep focus packages plus their upstream context.

    The report graph should stay focused on impact-summary packages, but
    those nodes still need enough ancestry to remain connected back to the
    project root when possible. Downstream children are intentionally
    excluded so the graph does not expand back into the full dependency DAG.
    """
    if not focus_packages:
        return list(edges)

    focus_norm = {str(name).lower().replace("_", "-") for name in focus_packages}
    incoming: dict[str, list[tuple[str, str]]] = {}
    for edge in edges:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        incoming.setdefault(child.lower().replace("_", "-"), []).append((parent, child))

    keep: set[tuple[str, str]] = set()
    stack = list(focus_norm)
    seen: set[str] = set()

    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for parent, child in incoming.get(current, []):
            keep.add((parent, child))
            stack.append(parent.lower().replace("_", "-"))

    filtered: list[dict] = []
    emitted: set[tuple[str, str]] = set()
    for edge in edges:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        key = (parent, child)
        if key not in keep or key in emitted:
            continue
        filtered.append({"parent": parent, "child": child})
        emitted.add(key)
    return filtered


def _render_dependency_graph_svg(report: dict) -> str | None:
    run = report.get("run", {})
    graph = report.get("graph", {})
    edges = graph.get("edges") or []
    if not edges:
        return None
    package_states = _report_dependency_graph_states(report)
    focus_packages = _report_dependency_graph_focus(report)
    graph_edges = _filter_report_graph_edges(edges, focus_packages)
    if not graph_edges:
        graph_edges = edges
    return render_svg_graph(
        graph_edges,
        graph_name=str(run.get("locator") or "changes_ai"),
        package_states=package_states,
    )


# Visual key swatches. Severities use fill colours from SEVERITY_PALETTE
# in graph.py; actions use border colours from ACTION_PALETTE. Order
# matches the visual hierarchy (severity left-to-right by tier, then
# remediation actions).
_GRAPH_KEY_SEVERITIES = [
    ("critical", "Critical", "#FEE2E2", "#991B1B"),
    ("high", "High", "#FFEDD5", "#9A3412"),
    ("medium", "Medium", "#FEF3C7", "#92400E"),
    ("low", "Low", "#DBEAFE", "#1E40AF"),
    ("unknown", "Unknown", "#F3F4F6", "#4B5563"),
]
_GRAPH_KEY_ACTIONS = [
    ("upgraded", "Upgraded", "#047857"),
    ("no_fix", "No fix available", "#7F1D1D"),
]


def _render_dependency_graph_key(report: dict) -> str | None:
    """Build an HTML colour key for the dependency graph.

    Adaptive: only emits swatches for severities and actions that
    actually appear in the current report. A run with no CRITICAL
    findings won't show a CRITICAL swatch.
    """
    states = _report_dependency_graph_states(report)
    focus_packages = _report_dependency_graph_focus(report)
    if focus_packages:
        focus_norm = {str(name).lower().replace("_", "-") for name in focus_packages}
        states = {
            name: state
            for name, state in states.items()
            if str(name).lower().replace("_", "-") in focus_norm
        }
    if not states:
        return None

    present_severities = set()
    present_actions = set()
    for record in states.values():
        if isinstance(record, dict):
            sev = record.get("severity")
            act = record.get("action")
        else:
            value = str(record).lower()
            if value in {"critical", "high", "medium", "low", "unknown"}:
                sev = value
                act = None
            elif value in {"upgraded", "no_fix"}:
                sev = None
                act = value
            else:
                sev = value
                act = None
        if sev:
            present_severities.add(sev.lower())
        if act:
            present_actions.add(act.lower())

    if not present_severities and not present_actions:
        return None

    items: list[str] = []

    for key, label, fill, text in _GRAPH_KEY_SEVERITIES:
        if key not in present_severities:
            continue
        items.append(
            f'<span class="key-item">'
            f'<span class="key-swatch" style="background:{fill};color:{text};'
            f'border-color:{text}">{label}</span>'
            f"</span>"
        )

    for key, label, border in _GRAPH_KEY_ACTIONS:
        if key not in present_actions:
            continue
        items.append(
            f'<span class="key-item">'
            f'<span class="key-swatch key-swatch--border" '
            f'style="border-color:{border}">{label}</span>'
            f"</span>"
        )

    if not items:
        return None

    return (
        '<div class="dependency-graph-key">'
        '<span class="key-label">Key:</span>' + "".join(items) + "</div>"
    )


def render_markdown_report(
    report: dict,
    dependency_graph_svg: str | None = None,
    dependency_graph_key: str | None = None,
) -> str:
    run = report.get("run", {})
    packages = report.get("packages", [])
    currency = report.get("currency", [])
    graph = report.get("graph", {})
    vulns = report.get("vulnerabilities", [])
    usage = report.get("usage", {})
    impacts = report.get("impact_reports", [])
    paths = report.get("remediation_paths", [])
    summary_narrative = (
        (report.get("executive_summary") or {}).get("narrative") or ""
    ).strip()

    summary_metadata = {
        "Run ID": str(run.get("id") or ""),
        "Target": str(run.get("locator") or "unknown"),
        "Packages analysed": str(len(packages)),
        "Vulnerabilities found": str(len(vulns)),
        "Remediation paths": str(len(paths)),
    }

    counts = _group_by(vulns, "severity")
    lines = [
        "# Changes AI Remediation Report",
        "",
        "## Executive Summary",
        "",
        f"<!-- executive-summary-meta: {json.dumps(summary_metadata, sort_keys=True)} -->",
        "",
        "## Vulnerabilities by Severity",
        "",
    ]

    if summary_narrative:
        lines[4:4] = [summary_narrative, ""]
    else:
        lines[4:4] = [
            f"- Run ID: {run.get('id')}",
            f"- Target: {run.get('locator') or 'unknown'}",
            f"- Packages analysed: {len(packages)}",
            f"- Vulnerabilities found: {len(vulns)}",
            f"- Remediation paths: {len(paths)}",
            "",
        ]

    if vulns:
        for severity in sorted(counts, key=lambda item: SEVERITY_ORDER.get(item, 99)):
            lines.append(f"- {severity}: {len(counts[severity])}")
        lines.append("")
        lines.extend(
            [
                "| Severity | Package | Installed | ID | Fixed In |",
                "|---|---|---|---|---|",
            ]
        )
        for vuln in sorted(
            vulns,
            key=lambda item: (
                SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 99),
                item.get("package", ""),
                item.get("cve_id", ""),
            ),
        ):
            fixed = ", ".join(vuln.get("fixed_versions") or []) or "none known"
            vuln_id = str(vuln.get("cve_id") or "UNKNOWN")
            lines.append(
                f"| {vuln.get('severity')} | {vuln.get('package')} | "
                f"{vuln.get('installed_version')} | {_render_osv_link(vuln_id)} | {fixed} |"
            )
    else:
        lines.append("No cached vulnerabilities for this run.")

    lines.extend(["", "## Currency Signals", ""])
    if currency:
        lines.extend(
            [
                "| Package | Installed | Latest | Latest Release | Cadence (days) | Signals |",
                "|---|---|---|---|---|---|",
            ]
        )
        for item in currency:
            signals = ", ".join(item.get("signals") or []) or "none"
            cadence = item.get("release_cadence_days")
            lines.append(
                f"| {item.get('package')} | {item.get('installed_version')} | {item.get('latest_version')} | "
                f"{item.get('latest_release_date') or 'unknown'} | {cadence if cadence is not None else 'unknown'} | {signals} |"
            )
    else:
        lines.append("No cached currency signals.")

    lines.extend(["", "## Used-Symbol Summary", ""])
    usage_records = usage.get("records", [])
    unresolved = usage.get("unresolved", [])
    if usage_records:
        grouped_usage = _group_by(usage_records, "package")
        for package in sorted(grouped_usage):
            symbols = sorted(
                {
                    item.get("symbol")
                    for item in grouped_usage[package]
                    if item.get("symbol")
                }
            )
            display = ", ".join(symbols[:12])
            if len(symbols) > 12:
                display += ", ..."
            lines.append(f"- {package}: {display}")
    else:
        lines.append("No cached resolved usage symbols.")
    if unresolved:
        lines.append("")
        lines.append("Unresolved usage flags:")
        for item in unresolved[:25]:
            location = f"{item.get('source_file')}:{item.get('line')}"
            package = f" ({item.get('package')})" if item.get("package") else ""
            lines.append(f"- {item.get('flag')}{package}: {location}")

    lines.extend(["", "## Impact Summary", ""])
    if impacts:
        lines.extend(
            ["| Package | Upgrade | Breakage | Confidence |", "|---|---|---|---|"]
        )
        for impact in impacts:
            upgrade = f"{impact.get('installed_version')} -> {impact.get('candidate_version')}"
            breakage = (
                f"{impact.get('probable_breakage')} ({impact.get('breakage_score')})"
            )
            lines.append(
                f"| {impact.get('package')} | {upgrade} | {breakage} | {impact.get('confidence')} |"
            )
        lines.append("")
        for impact in impacts:
            evidence = impact.get("evidence")
            citations = impact.get("evidence_citations") or []
            if not evidence and not citations:
                continue
            upgrade = f"{impact.get('installed_version')} -> {impact.get('candidate_version')}"
            lines.append(
                f"- {impact.get('package')} {upgrade}: {evidence or 'Evidence attached via citations only.'}"
            )
            for citation in citations:
                lines.append(
                    f"  Citation: {citation.get('source')} - {citation.get('label') or citation.get('url') or 'unknown'} ({citation.get('url') or 'no url'})"
                )
    else:
        lines.append("No cached impact reports.")

    lines.extend(["", "## Dependency Graph", ""])
    edges = graph.get("edges") or []
    if edges:
        if dependency_graph_svg:
            lines.extend(
                [
                    '<div class="dependency-graph-svg">',
                    dependency_graph_svg,
                    "</div>",
                ]
            )
            if dependency_graph_key:
                lines.append(dependency_graph_key)
        else:
            lines.append(f"Cached edges: {len(edges)}")
            lines.append("")
            for edge in edges[:25]:
                lines.append(f"- {edge.get('parent')} -> {edge.get('child')}")
            if len(edges) > 25:
                lines.append(f"- ... {len(edges) - 25} more edges")
    else:
        lines.append("No cached dependency graph edges.")

    lines.extend(["", "## Ranked Remediation Paths", ""])
    if paths:
        for path in paths:
            lines.append(
                f"### {str(path.get('path_type', '')).replace('_', ' ').title()}"
            )
            lines.append("")
            lines.append(
                f"Exposure: {path.get('exposure_score')}  "
                f"Breakage: {path.get('breakage_score')}  "
                f"Confidence: {path.get('confidence')}"
            )
            if path.get("rationale"):
                lines.extend(["", str(path["rationale"])])
            upgrades = path.get("upgrades") or []
            if upgrades:
                lines.extend(
                    ["", "| Package | From | To | Fixes |", "|---|---|---|---|"]
                )
                for upgrade in upgrades:
                    fixes = ", ".join(upgrade.get("fixes_cves") or [])
                    lines.append(
                        f"| {upgrade.get('package')} | {upgrade.get('from_version')} | "
                        f"{upgrade.get('to_version')} | {fixes} |"
                    )
            if path.get("cves_no_fix"):
                lines.append("")
                lines.append(f"No fix: {', '.join(path['cves_no_fix'])}")
            if path.get("cves_unresolved"):
                lines.append(f"Open: {', '.join(path['cves_unresolved'])}")
            lines.append("")
    else:
        lines.append("No cached remediation paths.")

    lines.extend(
        [
            "## Limitations and Confidence Notes",
            "",
            "- Cached reports reflect the data available when the run was recorded.",
            "- Missing usage, unresolved usage, missing changelog evidence, and LLM fallback paths lower confidence.",
            "- LLM-generated results are not guaranteed to be factually accurate and should be verified before being used as a basis for action.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_sarif_report(report: dict) -> str:
    vulns = report.get("vulnerabilities", [])
    paths = report.get("remediation_paths", [])
    currency = report.get("currency", [])
    source_metadata = report.get("run", {}).get("source_metadata") or {}
    dependency_uri = source_metadata.get("dependency_file") or "dependency-manifest"
    currency_by_package = {
        str(item.get("package") or "").lower(): item for item in currency
    }
    remediation_by_cve = {}
    for path in paths:
        for upgrade in path.get("upgrades") or []:
            for cve_id in upgrade.get("fixes_cves") or []:
                remediation_by_cve.setdefault(cve_id, []).append(
                    {
                        "path_type": path.get("path_type"),
                        "package": upgrade.get("package"),
                        "from_version": upgrade.get("from_version"),
                        "to_version": upgrade.get("to_version"),
                        "confidence": path.get("confidence"),
                    }
                )

    rules = []
    results = []
    seen_rules = set()
    for vuln in vulns:
        cve_id = vuln.get("cve_id") or "UNKNOWN"
        severity = vuln.get("severity", "UNKNOWN")
        if cve_id not in seen_rules:
            seen_rules.add(cve_id)
            rule_properties = {"problem.severity": severity}
            security_severity = SARIF_SECURITY_SEVERITY.get(severity)
            if security_severity is not None:
                rule_properties["security-severity"] = security_severity
            rules.append(
                {
                    "id": cve_id,
                    "name": cve_id,
                    "shortDescription": {"text": f"{cve_id} in {vuln.get('package')}"},
                    "fullDescription": {
                        "text": f"{severity} vulnerability affecting {vuln.get('package')}"
                    },
                    "properties": rule_properties,
                }
            )
        fixes = remediation_by_cve.get(cve_id, [])
        help_text = "No cached remediation path fixes this vulnerability."
        if fixes:
            help_text = "; ".join(
                f"{fix['path_type']}: {fix['package']} {fix['from_version']} -> {fix['to_version']}"
                for fix in fixes
            )
        results.append(
            {
                "ruleId": cve_id,
                "level": SARIF_LEVEL.get(severity, "none"),
                "message": {
                    "text": (
                        f"{severity} vulnerability {cve_id} "
                        f"affects {vuln.get('package')} {vuln.get('installed_version')}."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": dependency_uri},
                        }
                    }
                ],
                "properties": {
                    "package": vuln.get("package"),
                    "installed_version": vuln.get("installed_version"),
                    "fixed_versions": vuln.get("fixed_versions", []),
                    "remediation": fixes,
                    "help": help_text,
                    "currency": currency_by_package.get(
                        str(vuln.get("package") or "").lower()
                    ),
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Changes AI",
                        "informationUri": "https://github.com/pzanna/changes-ai",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_dot_report(report: dict) -> str:
    run = report.get("run", {})
    graph = report.get("graph", {})
    return render_dot_graph(
        graph.get("edges") or [],
        graph_name=str(run.get("locator") or "changes_ai"),
        package_states=_report_dependency_graph_states(report),
    )


def render_pdf_report(report: dict, css_path: str | None = None) -> bytes:
    """Render a styled PDF from the Markdown report via WeasyPrint.

    The styling lives in /templates/reports folder. See that module for customisation options.
    """
    markdown = render_markdown_report(
        report,
        dependency_graph_svg=_render_dependency_graph_svg(report),
        dependency_graph_key=_render_dependency_graph_key(report),
    )
    return render_report_pdf(markdown, css_path=css_path)


def render_html_report_bundle(
    report: dict, css_path: str | None = None
) -> dict[str, str]:
    """Render an HTML report bundle with index.html and style.css assets."""
    markdown = render_markdown_report(
        report,
        dependency_graph_svg=_render_dependency_graph_svg(report),
        dependency_graph_key=_render_dependency_graph_key(report),
    )
    return render_report_html_bundle(markdown, css_path=css_path)
