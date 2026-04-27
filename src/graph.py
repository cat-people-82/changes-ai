"""Dependency-graph helpers for persisted graph exports.

This module builds and renders the dependency graph used in Changes-AI
reports. The renderer adapts to graph size:

* Small graphs (<= 12 nodes)  -> ``dot`` directly, top-to-bottom.
* Medium graphs (13-80 nodes) -> ``unflatten`` preprocessor + ``dot``.
* Large graphs (> 80 nodes)   -> ``twopi`` radial layout.

Visual styling matches the corporate-serious aesthetic used by the PDF
report (navy nodes, gold project root, light grid background). When
``vulnerable_packages`` is supplied to ``render_svg_graph``, those
nodes are highlighted in red so the reader can see remediation impact
at a glance.
"""

from __future__ import annotations

import re
import subprocess
from typing import Iterable

# ---------------------------------------------------------------------------
# Layout tuning
# ---------------------------------------------------------------------------

# Graph-size thresholds for engine selection. Tuned for A4 portrait pages.
SMALL_GRAPH_NODES = 12
LARGE_GRAPH_NODES = 40

# unflatten parameters for medium graphs.
#   -l N  : maximum chain length before wrapping
#   -c N  : maximum columns at each rank
UNFLATTEN_CHAIN = "3"
UNFLATTEN_COLUMNS = "5"

# Visual palette (matches changes-ai-report.css)
PALETTE = {
    "bg": "#ffffff",
    "node_fill": "#f8f9fb",
    "node_border": "#d1d5db",
    "node_text": "#1a1a1a",
    "root_fill": "#0B2545",
    "root_text": "#ffffff",
    "edge": "#9ca3af",
    "font": "Helvetica,Arial,sans-serif",
}

# Per-state palette for vulnerability and remediation states. Mirrors the
# pill colours used in changes-ai-report.css so the graph reads as part
# of the same document as the vulnerability and impact tables.
STATE_PALETTE: dict[str, dict[str, str]] = {
    "critical": {"fill": "#FEE2E2", "border": "#B91C1C", "text": "#991B1B"},
    "high": {"fill": "#FFEDD5", "border": "#C2410C", "text": "#9A3412"},
    "medium": {"fill": "#FEF3C7", "border": "#B45309", "text": "#92400E"},
    "low": {"fill": "#DBEAFE", "border": "#1E40AF", "text": "#1E40AF"},
    "upgraded": {"fill": "#D1FAE5", "border": "#047857", "text": "#065F46"},
    "no_fix": {"fill": "#FEE2E2", "border": "#7F1D1D", "text": "#7F1D1D"},
    "unknown": {"fill": "#F3F4F6", "border": "#9CA3AF", "text": "#4B5563"},
}

# Aliases so callers can pass the OSV severity strings directly.
STATE_ALIASES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
    "UPGRADED": "upgraded",
    "NO_FIX": "no_fix",
    "NO-FIX": "no_fix",
}


# ---------------------------------------------------------------------------
# Edge construction
# ---------------------------------------------------------------------------


def _normalise_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _concrete_version(requirement: str | None) -> str | None:
    if not requirement:
        return None
    stripped = requirement.strip()
    exact_match = re.match(r"^==\s*(\S+)$", stripped)
    if exact_match:
        return exact_match.group(1)
    if not re.search(r"[<>=!~;, \[\]]", stripped) and re.match(
        r"^\d+(?:[.\w+-]*\d)?$", stripped
    ):
        return stripped
    return None


def build_dependency_edges(
    packages: dict,
    *,
    project_node: str = "project",
    installed_versions: dict | None = None,
    libraries_client=None,
    include_transitive: bool = False,
) -> list[dict]:
    """Build persisted dependency edges for the current run."""
    edges: set[tuple[str, str]] = set()
    version_lookup = {
        _normalise_name(name): version
        for name, version in (installed_versions or {}).items()
    }

    for name in packages:
        edges.add((project_node, name))

    if include_transitive and libraries_client is not None:
        for name, requirement in packages.items():
            resolved = version_lookup.get(_normalise_name(name)) or _concrete_version(
                requirement
            )
            if not resolved:
                continue
            for dependency in libraries_client.get_dependencies(name, resolved):
                edges.add((name, dependency))

    return [{"parent": parent, "child": child} for parent, child in sorted(edges)]


def build_package_states(
    report: dict,
    *,
    chosen_path: str | None = None,
    include_upgrades: bool = True,
) -> dict[str, str]:
    """Build a ``package_states`` dict from a Changes-AI run report.

    Walks the report's ``vulnerabilities`` and ``remediation_paths`` to
    produce a mapping suitable for ``render_svg_graph`` and
    ``filter_vulnerability_subgraph``.

    ``chosen_path`` selects which remediation path's upgrades to mark as
    upgraded — defaults to the first ``balanced`` path, then the first
    path of any kind. Pass ``include_upgrades=False`` to render the
    pre-remediation picture (vulnerabilities only, no green nodes).
    """
    states: dict[str, str] = {}

    # Severity-tier states from vulnerability records.
    paths = report.get("remediation_paths") or []
    no_fix_cves = set()
    for path in paths:
        for cve in path.get("cves_no_fix") or []:
            no_fix_cves.add(cve)

    for vuln in report.get("vulnerabilities") or []:
        package = vuln.get("package")
        severity = (vuln.get("severity") or "UNKNOWN").upper()
        if not package:
            continue
        # If this CVE has no fix in any path, mark the package as no_fix
        # rather than its severity tier — the distinction matters more
        # to the reader than the underlying severity.
        cve_id = vuln.get("cve_id")
        if cve_id and cve_id in no_fix_cves:
            states[package] = "no_fix"
        else:
            states.setdefault(package, severity.lower())

    if not include_upgrades or not paths:
        return states

    # Pick a remediation path: explicit > balanced > first available.
    selected = None
    if chosen_path:
        for path in paths:
            if path.get("path_type") == chosen_path:
                selected = path
                break
    if selected is None:
        for path in paths:
            if path.get("path_type") == "balanced":
                selected = path
                break
    if selected is None:
        selected = paths[0]

    for upgrade in selected.get("upgrades") or []:
        package = upgrade.get("package")
        if not package:
            continue
        # Upgraded state overrides severity — the graph shows the
        # post-remediation picture by default.
        states[package] = "upgraded"

    return states


def filter_vulnerability_subgraph(
    edges: list[dict],
    affected: Iterable[str] | dict[str, str],
    *,
    include_parents: bool = True,
) -> list[dict]:
    """Return only the edges that touch affected packages.

    ``affected`` may be either an iterable of package names or a
    ``package_states`` dict (in which case the dict keys are used as the
    affected set — handy for passing the same value to both this filter
    and ``render_svg_graph``).

    Useful for PDF reports where rendering 200-node dependency graphs
    is illegible. By default, includes the immediate parents of any
    affected package so the reader can see what depends on what.
    """
    if isinstance(affected, dict):
        names = affected.keys()
    else:
        names = affected
    affected_set = {_normalise_name(name) for name in names}
    if not affected_set:
        return list(edges)

    keep: set[tuple[str, str]] = set()
    for edge in edges:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        if _normalise_name(child) in affected_set:
            keep.add((parent, child))
            if include_parents:
                # Walk upwards: any edge ending at `parent` is relevant too.
                for upstream in edges:
                    if str(upstream.get("child") or "") == parent:
                        keep.add(
                            (
                                str(upstream.get("parent") or ""),
                                str(upstream.get("child") or ""),
                            )
                        )
        elif _normalise_name(parent) in affected_set:
            keep.add((parent, child))

    return [{"parent": parent, "child": child} for parent, child in sorted(keep)]


# ---------------------------------------------------------------------------
# DOT rendering
# ---------------------------------------------------------------------------


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _node_count(edges: list[dict]) -> int:
    nodes: set[str] = set()
    for edge in edges:
        nodes.add(str(edge.get("parent") or ""))
        nodes.add(str(edge.get("child") or ""))
    return len(nodes)


def _identify_roots(edges: list[dict]) -> set[str]:
    parents = {str(edge.get("parent") or "") for edge in edges}
    children = {str(edge.get("child") or "") for edge in edges}
    return parents - children


def _resolve_state(state: str) -> str | None:
    """Map a state value (any case, with or without aliases) to a key
    in STATE_PALETTE. Returns ``None`` for unrecognised states."""
    if not state:
        return None
    normalised = STATE_ALIASES.get(state.upper(), state.lower())
    return normalised if normalised in STATE_PALETTE else None


def render_dot_graph(
    edges: list[dict],
    *,
    graph_name: str = "changes_ai",
    package_states: dict[str, str] | None = None,
    rankdir: str = "TB",
    ranksep: float = 0.6,
) -> str:
    """Render a styled DOT graph from persisted edges.

    ``package_states`` maps package names to one of:
    ``critical`` / ``high`` / ``medium`` / ``low`` (severity tiers),
    ``upgraded`` (remediation target),
    ``no_fix`` (vulnerable but no fix available),
    ``unknown``. The OSV severity strings (CRITICAL, HIGH, ...) are
    accepted as aliases.

    When a package appears in both a severity tier and as ``upgraded``,
    the upgraded state wins — the graph is meant to show the *post-
    remediation* picture. Pre-remediation views can be rendered by
    omitting upgraded entries from ``package_states``.
    """
    states = {
        _normalise_name(name): _resolve_state(state)
        for name, state in (package_states or {}).items()
    }
    states = {k: v for k, v in states.items() if v is not None}
    roots = _identify_roots(edges)

    lines = [
        f'digraph "{_escape(graph_name)}" {{',
        f'  bgcolor="{PALETTE["bg"]}";',
        f'  fontname="{PALETTE["font"]}";',
        f'  rankdir="{rankdir}";',
        '  nodesep="0.35";',
        f'  ranksep="{ranksep}";',
        '  splines="spline";',
        '  pad="0.3";',
        (
            f'  node [fontname="{PALETTE["font"]}", fontsize="10", '
            f'shape="box", style="rounded,filled", '
            f'fillcolor="{PALETTE["node_fill"]}", color="{PALETTE["node_border"]}", '
            f'fontcolor="{PALETTE["node_text"]}", margin="0.14,0.07", height="0.32"];'
        ),
        (
            f'  edge [fontname="{PALETTE["font"]}", fontsize="9", '
            f'arrowsize="0.6", penwidth="0.8", color="{PALETTE["edge"]}"];'
        ),
    ]

    # Per-node styling overrides (roots first, then state-coloured nodes)
    all_nodes: set[str] = set()
    for edge in edges:
        all_nodes.add(str(edge.get("parent") or ""))
        all_nodes.add(str(edge.get("child") or ""))

    for node in sorted(all_nodes):
        normalised = _normalise_name(node)
        if node in roots:
            lines.append(
                f'  "{_escape(node)}" '
                f'[fillcolor="{PALETTE["root_fill"]}", '
                f'fontcolor="{PALETTE["root_text"]}", '
                f'color="{PALETTE["root_fill"]}", '
                f'penwidth="0", fontsize="11"];'
            )
            continue
        state = states.get(normalised)
        if state is None:
            continue
        colours = STATE_PALETTE[state]
        lines.append(
            f'  "{_escape(node)}" '
            f'[fillcolor="{colours["fill"]}", '
            f'fontcolor="{colours["text"]}", '
            f'color="{colours["border"]}", penwidth="1.2"];'
        )

    for edge in edges:
        parent = _escape(str(edge.get("parent") or ""))
        child = _escape(str(edge.get("child") or ""))
        lines.append(f'  "{parent}" -> "{child}";')

    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SVG rendering
# ---------------------------------------------------------------------------


def _max_depth(edges: list[dict]) -> int:
    """Return the longest path length (in edges) from any root."""
    children_of: dict[str, list[str]] = {}
    for edge in edges:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        children_of.setdefault(parent, []).append(child)

    roots = _identify_roots(edges)
    if not roots:
        return 0

    def dfs(node: str, seen: set[str]) -> int:
        if node in seen:
            return 0
        seen = seen | {node}
        kids = children_of.get(node, [])
        if not kids:
            return 0
        return 1 + max(dfs(child, seen) for child in kids)

    return max(dfs(root, set()) for root in roots)


def _select_engine(edges: list[dict]) -> tuple[str, bool, float]:
    """Choose layout engine, whether to preprocess with unflatten, and the
    rank separation to use.

    Returns ``(engine, use_unflatten, ranksep)``.

    Decision logic:
    * Shallow graphs (depth <= 1) with > 8 nodes go to ``twopi`` (radial).
      Flat graphs with one root + N leaves are precisely the case ``dot``
      can't handle without becoming wide-and-thin. Radial naturally fits
      a square aspect ratio.
    * Small hierarchical graphs use ``dot`` directly.
    * Medium hierarchical graphs use ``unflatten`` + ``dot``.
    * Very large graphs fall back to ``twopi`` regardless of depth.
    """
    n = _node_count(edges)
    depth = _max_depth(edges)
    # print(f"Graph has {n} nodes and depth {depth}. Choosing layout engine...")

    # Shallow + many leaves: radial is the right shape.
    if depth <= 1 and n > 3:
        return "twopi", False, 3.0

    # Hierarchical small graph
    if n <= SMALL_GRAPH_NODES:
        return "dot", False, 0.6

    # Hierarchical medium graph: unflatten helps dot lay it out as a grid
    if n <= LARGE_GRAPH_NODES:
        return "dot", True, 0.6

    # Very large: radial is the only thing that fits
    return "twopi", False, 3.0


def _run(cmd: list[str], stdin: str) -> tuple[int, str]:
    """Run a subprocess, returning (returncode, stdout). Empty stdout on error."""
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return 1, ""
    return result.returncode, result.stdout


def render_svg_graph(
    edges: list[dict],
    *,
    graph_name: str = "changes_ai",
    package_states: dict[str, str] | None = None,
    rankdir: str | None = None,
) -> str | None:
    """Render a Graphviz SVG from persisted edges.

    Returns ``None`` when Graphviz is unavailable or rendering fails.
    The layout engine is selected automatically based on graph size and
    shape; pass ``rankdir`` to override the default top-to-bottom
    orientation (ignored for ``twopi``, which is radial).

    See ``render_dot_graph`` for the format of ``package_states``.
    """
    if not edges:
        return None

    engine, use_unflatten, ranksep = _select_engine(edges)
    effective_rankdir = rankdir or "TB"
    dot_graph = render_dot_graph(
        edges,
        graph_name=graph_name,
        package_states=package_states,
        rankdir=effective_rankdir,
        ranksep=ranksep,
    )

    if use_unflatten:
        rc, gridded = _run(
            ["unflatten", "-l", UNFLATTEN_CHAIN, "-c", UNFLATTEN_COLUMNS],
            dot_graph,
        )
        if rc == 0 and gridded.strip():
            dot_graph = gridded

    rc, output = _run([engine, "-Tsvg"], dot_graph)
    if rc != 0 or not output.strip():
        return None

    match = re.search(r"(<svg\b.*</svg>)", output, re.DOTALL)
    if not match:
        return None
    return match.group(1).strip()
