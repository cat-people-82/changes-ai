"""
AST-based usage analysis for Changes AI.

Walks a project's Python source tree and maps each installed package
to the symbols the project actually references, flagging patterns that
cannot be resolved statically.
"""

import ast
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class UsageRecord:
    """One resolved symbol reference to an installed package."""

    package: str  # resolved package name as returned by the lookup (preserves original case/hyphens)
    module: str  # dotted module path as written in the import statement
    symbol: str  # referenced name; the module itself if only the module is used
    source_file: str  # path relative to the project root
    line: int  # 1-based line number


@dataclass
class UnresolvedUsage:
    """A usage pattern that cannot be statically resolved."""

    package: str  # best-guess package name (may be empty string if unknown)
    flag: str  # "star_import" | "dynamic_import" | "entry_point" | "reflection" | "parse_error" | "unreadable_file"
    source_file: str
    line: int


@dataclass
class UsageReport:
    """Aggregated result of analysing one project."""

    records: list = field(default_factory=list)  # list[UsageRecord]
    unresolved: list = field(default_factory=list)  # list[UnresolvedUsage]

    def packages_used(self) -> set:
        """Return the set of package names with at least one resolved reference."""
        return {r.package for r in self.records}

    def packages_with_flags(self) -> set:
        """Return the set of package names with at least one unresolved flag."""
        return {u.package for u in self.unresolved if u.package}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise(name: str) -> str:
    """Lowercase and replace hyphens/dots with underscores for comparison."""
    return name.lower().replace("-", "_").replace(".", "_")


def _build_norm_lookup(packages: dict, top_level_map: dict | None = None) -> dict:
    """Build normalised-name → original-name lookup from a packages dict.

    *top_level_map* is an optional {import_top_level: package_name} dict (e.g.
    ``{"dotenv": "python-dotenv", "PIL": "Pillow"}``).  When provided, each
    import-level key is added to the lookup so that packages whose PyPI name
    differs from their top-level import name are still resolved correctly.

    When two package names normalise to the same key (e.g. 'google-auth' and
    'google_auth'), the hyphenated form takes priority as the canonical PyPI name.
    """
    # Write underscore forms first so hyphenated forms overwrite them.
    lookup: dict[str, str] = {}
    for name in packages:
        if "-" not in name:
            lookup[_normalise(name)] = name
    for name in packages:
        if "-" in name:
            lookup[_normalise(name)] = name
    # Overlay top-level import names (e.g. "dotenv" → "python-dotenv").
    if top_level_map:
        for import_name, pkg_name in top_level_map.items():
            key = _normalise(import_name)
            if key not in lookup:  # don't override a direct name match
                lookup[key] = pkg_name
    return lookup


def _read_top_level_map(venv_path) -> dict:
    """Read ``top_level.txt`` files from a venv and return {import_name: pkg_name}.

    Many packages ship a ``<name>-<ver>.dist-info/top_level.txt`` that lists the
    top-level import names they provide (one per line).  For example,
    ``python_dotenv-1.0.dist-info/top_level.txt`` contains ``dotenv``.

    Returns an empty dict if *venv_path* is None or doesn't exist.
    """
    if venv_path is None:
        return {}
    venv_path = Path(venv_path)
    # Locate site-packages using numeric version sort (same as VenvParser._find_site_packages).
    candidates = sorted(
        venv_path.glob("lib/python*/site-packages"),
        key=lambda p: tuple(int(x) for x in re.findall(r"\d+", p.parent.name)),
    )
    if not candidates:
        return {}
    site = candidates[-1]
    top_level: dict[str, str] = {}
    for dist_info in site.glob("*.dist-info"):
        tl_file = dist_info / "top_level.txt"
        meta_file = dist_info / "METADATA"
        if not tl_file.exists():
            continue
        # Read package name from METADATA
        pkg_name: str | None = None
        try:
            with meta_file.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip() == "":
                        break
                    if line.startswith("Name:"):
                        pkg_name = line.split(":", 1)[1].strip()
                        break
        except FileNotFoundError:
            continue
        if not pkg_name:
            continue
        try:
            for import_name in tl_file.read_text(encoding="utf-8").splitlines():
                import_name = import_name.strip()
                if import_name:
                    top_level[import_name] = pkg_name
        except OSError:
            continue
    return top_level


def _resolve_package(module: str, norm_lookup: dict) -> str | None:
    """Map a dotted module name to the package that owns it.

    *norm_lookup* is a pre-built normalised-name → original-name dict,
    as returned by :func:`_build_norm_lookup`.

    Strategy: walk from the full dotted name up to the top-level component,
    checking each prefix against the normalised lookup.
    Returns the first match found (longest prefix wins), or None.
    """
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        candidate = "_".join(parts[:i]).lower()
        if candidate in norm_lookup:
            return norm_lookup[candidate]
    return None


# ---------------------------------------------------------------------------
# AST walker
# ---------------------------------------------------------------------------

_SKIP_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    ".tox",
    "node_modules",
    "build",
    "dist",
}

_DYNAMIC_IMPORT_CALLS = {
    ("importlib", "import_module"),
    # bare __import__("x") is caught via the name_pair[1] == "__import__" guard below
}
_ENTRY_POINT_CALLS = {
    ("pkg_resources", "iter_entry_points"),
    ("importlib.metadata", "entry_points"),
    ("", "entry_points"),
}


def _call_dotted_name(node: ast.Call) -> tuple | None:
    """Return (module, attr) for a call target, or ("", name) for a bare call.

    Collapses chained attribute access so that both ``mod.func(...)`` and
    ``pkg.sub.func(...)`` are handled — the full dotted prefix is returned as
    the module portion (e.g. ``("importlib.metadata", "entry_points")``).
    """
    if isinstance(node.func, ast.Name):
        return "", node.func.id

    if isinstance(node.func, ast.Attribute):
        attr = node.func.attr
        value = node.func.value
        parts: list[str] = []
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
            parts.reverse()
            return ".".join(parts), attr

    return None


def _iter_python_files(root: Path):
    """Yield all .py files under *root*, skipping virtual-env and cache dirs."""
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _walk_ast(
    tree: ast.AST,
    source_file: str,
    norm_lookup: dict,
    records: list,
    unresolved: list,
    local_names: set | None = None,
) -> None:
    """Walk *tree* and populate *records* and *unresolved* in-place."""
    # Pass 1: collect local name → package mappings for this file
    local_pkg: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                pkg = _resolve_package(alias.name, norm_lookup)
                if pkg:
                    local_name = alias.asname or alias.name.split(".")[0]
                    local_pkg[local_name] = pkg
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            pkg = _resolve_package(module, norm_lookup)
            if pkg and not (node.names and node.names[0].name == "*"):
                for alias in node.names:
                    local_pkg[alias.asname or alias.name] = pkg

    # Pass 2: emit records/unresolved — reuses local_pkg to avoid re-resolving imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                pkg = local_pkg.get(local_name)
                if pkg:
                    records.append(
                        UsageRecord(
                            package=pkg,
                            module=alias.name,
                            symbol=local_name,
                            source_file=source_file,
                            line=node.lineno,
                        )
                    )

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.names and node.names[0].name == "*":
                pkg = _resolve_package(module, norm_lookup)
                if pkg:  # skip star-imports of local/stdlib modules
                    unresolved.append(
                        UnresolvedUsage(
                            package=pkg,
                            flag="star_import",
                            source_file=source_file,
                            line=node.lineno,
                        )
                    )
            else:
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    pkg = local_pkg.get(local_name)
                    if pkg:
                        records.append(
                            UsageRecord(
                                package=pkg,
                                module=module,
                                symbol=alias.name,
                                source_file=source_file,
                                line=node.lineno,
                            )
                        )

        elif isinstance(node, ast.Call):
            name_pair = _call_dotted_name(node)
            if name_pair is None:
                continue

            if name_pair in _DYNAMIC_IMPORT_CALLS or name_pair[1] == "__import__":
                # Try to resolve the module name when it's a string literal.
                mod_name = None
                if (
                    node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    mod_name = node.args[0].value
                if mod_name is not None:
                    top = _normalise(mod_name.split(".")[0])
                    if local_names and top in local_names:
                        pass  # local module — skip
                    else:
                        pkg = _resolve_package(mod_name, norm_lookup)
                        if pkg:  # known package — flag it with attribution
                            unresolved.append(
                                UnresolvedUsage(
                                    package=pkg,
                                    flag="dynamic_import",
                                    source_file=source_file,
                                    line=node.lineno,
                                )
                            )
                        # else: stdlib module — skip entirely
                else:
                    # Truly dynamic (variable argument) — flag without package
                    unresolved.append(
                        UnresolvedUsage(
                            package="",
                            flag="dynamic_import",
                            source_file=source_file,
                            line=node.lineno,
                        )
                    )

            elif name_pair in _ENTRY_POINT_CALLS:
                unresolved.append(
                    UnresolvedUsage(
                        package="",
                        flag="entry_point",
                        source_file=source_file,
                        line=node.lineno,
                    )
                )

            elif name_pair[1] in ("getattr", "vars") and node.args:
                first = node.args[0]
                target_name = None
                if isinstance(first, ast.Name):
                    target_name = first.id
                elif isinstance(first, ast.Attribute) and isinstance(
                    first.value, ast.Name
                ):
                    target_name = first.value.id
                if target_name and target_name in local_pkg:
                    unresolved.append(
                        UnresolvedUsage(
                            package=local_pkg[target_name],
                            flag="reflection",
                            source_file=source_file,
                            line=node.lineno,
                        )
                    )


def analyse_usage(source_root, packages: dict, venv_path=None) -> UsageReport:
    """Walk *source_root* and return a UsageReport for *packages*.

    *source_root* — str or Path to the project directory.
    *packages*    — {name: version} dict as returned by DependencyParser / VenvParser.
    *venv_path*   — optional path to the project's venv; used to read
                    ``top_level.txt`` files so packages whose PyPI name differs
                    from their import name (e.g. ``python-dotenv`` → ``dotenv``)
                    are correctly resolved.
    """
    source_root = Path(source_root)

    # Collect local importable names from actual Python files under source_root.
    # Using _iter_python_files (which already skips venv/cache dirs) means we
    # only treat a directory as a local package if it actually contains .py files,
    # preventing asset/data directories from shadowing third-party packages.
    local_names: set[str] = set()
    for py_file in _iter_python_files(source_root):
        rel_parts = py_file.relative_to(source_root).parts
        if py_file.stem != "__init__":
            local_names.add(_normalise(py_file.stem))
        for part in rel_parts[:-1]:
            if part and part not in _SKIP_DIRS and not part.startswith("."):
                local_names.add(_normalise(part))

    top_level_map = _read_top_level_map(venv_path)
    norm_lookup = _build_norm_lookup(packages, top_level_map)
    # Remove any local names that accidentally shadow a third-party package.
    for name in local_names:
        norm_lookup.pop(name, None)
    records: list = []
    unresolved: list = []

    for py_file in _iter_python_files(source_root):
        rel = _relative(py_file, source_root)
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as exc:
            unresolved.append(
                UnresolvedUsage(
                    package="",
                    flag="parse_error",
                    source_file=rel,
                    line=exc.lineno or 1,
                )
            )
            continue
        except OSError:
            unresolved.append(
                UnresolvedUsage(
                    package="",
                    flag="unreadable_file",
                    source_file=rel,
                    line=1,
                )
            )
            continue
        _walk_ast(tree, rel, norm_lookup, records, unresolved, local_names)

    return UsageReport(records=records, unresolved=unresolved)
