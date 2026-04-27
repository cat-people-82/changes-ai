"""Dependency-graph helpers for persisted graph exports."""

from __future__ import annotations

import re
import subprocess


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


def render_dot_graph(edges: list[dict], *, graph_name: str = "changes_ai") -> str:
    """Render a DOT graph from persisted edges."""
    max_root_row = 4

    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    adjacency: dict[str, list[str]] = {}
    parents: set[str] = set()
    children: set[str] = set()
    for edge in edges:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        parents.add(parent)
        children.add(child)
        adjacency.setdefault(parent, []).append(child)

    lines = [
        f'digraph "{_escape(graph_name)}" {{',
        '  fontname="Helvetica,Arial,sans-serif";',
        '  rankdir="TB";',
        '  nodesep="0.25";',
        '  ranksep="0.35";',
        '  node [fontname="Helvetica,Arial,sans-serif", fontsize="10", margin="0.08,0.04"];',
        '  edge [fontname="Helvetica,Arial,sans-serif", fontsize="9", arrowsize="0.6", penwidth="0.8"];',
    ]

    roots = sorted(parents - children)
    wrapped_roots: set[str] = set()
    for root_index, root in enumerate(roots):
        direct_children = sorted(adjacency.get(root, []))
        if len(direct_children) <= max_root_row:
            continue
        wrapped_roots.add(root)

        previous_helper = ""
        for chunk_index in range(0, len(direct_children), max_root_row):
            helper = f"__changes_ai_wrap_{root_index}_{chunk_index // max_root_row}"
            chunk = direct_children[chunk_index : chunk_index + max_root_row]
            escaped_helper = _escape(helper)
            escaped_root = _escape(root)

            lines.append(
                f'  "{escaped_helper}" [shape=point, width=0, height=0, label="", style=invis];'
            )
            if previous_helper:
                lines.append(
                    f'  "{_escape(previous_helper)}" -> "{escaped_helper}" [style=invis, weight=100];'
                )
            else:
                lines.append(
                    f'  "{escaped_root}" -> "{escaped_helper}" [style=invis, weight=100];'
                )

            rank_members = " ".join(
                f'"{_escape(member)}"' for member in [helper, *chunk]
            )
            lines.append(f"  {{ rank=same; {rank_members}; }}")
            for child in chunk:
                lines.append(
                    f'  "{escaped_helper}" -> "{_escape(child)}" [style=invis, weight=10];'
                )
            previous_helper = helper

    for edge in edges:
        parent_raw = str(edge.get("parent") or "")
        child_raw = str(edge.get("child") or "")
        parent = _escape(parent_raw)
        child = _escape(child_raw)
        if parent_raw in wrapped_roots:
            lines.append(f'  "{parent}" -> "{child}" [constraint=false];')
        else:
            lines.append(f'  "{parent}" -> "{child}";')
    lines.append("}")
    return "\n".join(lines)


def render_svg_graph(
    edges: list[dict], *, graph_name: str = "changes_ai"
) -> str | None:
    """Render a Graphviz SVG from persisted edges.

    Returns ``None`` when Graphviz is unavailable or rendering fails.
    """
    dot_graph = render_dot_graph(edges, graph_name=graph_name)
    try:
        result = subprocess.run(
            ["dot", "-Tsvg"],
            input=dot_graph,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None

    if result.returncode != 0 or not result.stdout.strip():
        return None

    match = re.search(r"(<svg\b.*</svg>)", result.stdout, re.DOTALL)
    if not match:
        return None
    return match.group(1).strip()
