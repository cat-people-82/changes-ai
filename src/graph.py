"""Dependency-graph helpers for persisted graph exports."""

from __future__ import annotations

import re


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

    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    lines = [f'digraph "{_escape(graph_name)}" {{', '  rankdir="LR";']
    for edge in edges:
        parent = _escape(str(edge.get("parent") or ""))
        child = _escape(str(edge.get("child") or ""))
        lines.append(f'  "{parent}" -> "{child}";')
    lines.append("}")
    return "\n".join(lines)
