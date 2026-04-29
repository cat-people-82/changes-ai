from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript

from .base import UsageRecord, UsageResult

JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {
    "node_modules",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "coverage",
}
NODE_BUILTINS = {
    "fs",
    "path",
    "crypto",
    "os",
    "child_process",
    "util",
    "stream",
    "events",
    "http",
    "https",
    "url",
    "querystring",
    "buffer",
    "process",
    "assert",
    "zlib",
    "tls",
    "net",
    "dns",
    "worker_threads",
}


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def _normalise(name: str) -> str:
    return name.lower()


def _build_lookup(packages: dict) -> dict[str, str]:
    return {_normalise(name): name for name in packages}


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_gitignore(root: Path) -> list[str]:
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []
    try:
        lines = gitignore.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _warn(f"failed to read .gitignore: {exc}")
        return []
    patterns = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        patterns.append(stripped)
    return patterns


def _matches_gitignore(rel_posix: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/"):
            prefix = pattern.rstrip("/")
            if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
                return True
        if fnmatch.fnmatch(rel_posix, pattern):
            return True
    return False


def _iter_source_files(root: Path):
    patterns = _read_gitignore(root)
    for current_root, dirs, files in os.walk(root, topdown=True):
        current_path = Path(current_root)
        rel_root = _relative(current_path, root)
        filtered_dirs = []
        for name in dirs:
            if name in SKIP_DIRS:
                continue
            if name.startswith(".") and name not in {".next", ".nuxt"}:
                continue
            rel_path = name if rel_root == "." else f"{rel_root}/{name}"
            if _matches_gitignore(rel_path, patterns):
                continue
            filtered_dirs.append(name)
        dirs[:] = filtered_dirs
        for name in files:
            path = current_path / name
            if path.suffix not in JS_SUFFIXES:
                continue
            rel_path = _relative(path, root).replace("\\", "/")
            if _matches_gitignore(rel_path, patterns):
                continue
            yield path


def _parser_for_suffix(suffix: str) -> Parser:
    parser = Parser()
    if suffix in {".ts", ".tsx"}:
        lang_fn = (
            tree_sitter_typescript.language_tsx
            if suffix == ".tsx"
            else tree_sitter_typescript.language_typescript
        )
    else:
        lang_fn = tree_sitter_javascript.language
    parser.language = Language(lang_fn())
    return parser


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _string_value(node, source_bytes: bytes) -> str | None:
    if node is None or node.type != "string":
        return None
    value = _node_text(node, source_bytes)
    if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
        return value[1:-1]
    return None


def _package_from_specifier(specifier: str, lookup: dict[str, str]) -> str | None:
    if not specifier or specifier.startswith(("./", "../", "/")):
        return None
    if specifier in NODE_BUILTINS:
        return None
    if specifier.startswith("@"):
        parts = specifier.split("/")
        if len(parts) < 2:
            return None
        package = "/".join(parts[:2])
    else:
        package = specifier.split("/", 1)[0]
    if package in NODE_BUILTINS:
        return None
    return lookup.get(_normalise(package))


def _first_child_of_type(node, node_type: str):
    for child in node.children:
        if child.type == node_type:
            return child
    return None


def _children_of_type(node, node_type: str):
    return [child for child in node.children if child.type == node_type]


def analyse_project(source_root, packages: dict) -> UsageResult:
    source_root = Path(source_root)
    lookup = _build_lookup(packages)
    records: list[UsageRecord] = []
    unresolved: list[dict] = []

    for source_file in _iter_source_files(source_root):
        rel = _relative(source_file, source_root).replace("\\", "/")
        try:
            source = source_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unresolved.append(
                {
                    "flag": "unreadable_file",
                    "package": None,
                    "source_file": rel,
                    "line": 1,
                }
            )
            continue

        parser = _parser_for_suffix(source_file.suffix)
        source_bytes = source.encode("utf-8")
        tree = parser.parse(source_bytes)
        namespace_imports: dict[str, str] = {}

        def add_record(package: str, symbol: str, node) -> None:
            records.append(
                UsageRecord(
                    package=package,
                    symbol=symbol,
                    source_file=rel,
                    line=node.start_point[0] + 1,
                )
            )

        def add_unresolved(flag: str, package: str | None, node) -> None:
            unresolved.append(
                {
                    "flag": flag,
                    "package": package,
                    "source_file": rel,
                    "line": node.start_point[0] + 1,
                }
            )

        def visit(node) -> None:
            if node.type == "import_statement":
                module_node = _first_child_of_type(node, "string")
                specifier = _string_value(module_node, source_bytes)
                package = _package_from_specifier(specifier or "", lookup)
                if package:
                    clause = _first_child_of_type(node, "import_clause")
                    if clause is not None:
                        for child in clause.children:
                            if child.type == "identifier":
                                add_record(package, "default", child)
                            elif child.type == "namespace_import":
                                alias = _first_child_of_type(child, "identifier")
                                add_record(package, "*", child)
                                if alias is not None:
                                    namespace_imports[_node_text(alias, source_bytes)] = package
                            elif child.type == "named_imports":
                                for spec in _children_of_type(child, "import_specifier"):
                                    imported = None
                                    for item in spec.children:
                                        if item.type in {"identifier", "property_identifier"}:
                                            imported = _node_text(item, source_bytes)
                                            break
                                    if imported:
                                        add_record(package, imported, spec)
                    else:
                        add_record(package, "default", node)

            elif node.type == "variable_declarator":
                value = node.children[-1] if node.children else None
                if value is not None and value.type == "call_expression":
                    callee = value.children[0] if value.children else None
                    if callee is not None and _node_text(callee, source_bytes) == "require":
                        args = _first_child_of_type(value, "arguments")
                        first_arg = None
                        if args is not None:
                            for child in args.children:
                                if child.type not in {"(", ")", ","}:
                                    first_arg = child
                                    break
                        if first_arg is None:
                            return
                        specifier = _string_value(first_arg, source_bytes)
                        if specifier is None:
                            add_unresolved("dynamic_require", None, value)
                            return
                        package = _package_from_specifier(specifier, lookup)
                        if package is None:
                            return
                        target = node.children[0] if node.children else None
                        if target is None:
                            return
                        if target.type == "object_pattern":
                            for child in target.children:
                                if child.type in {
                                    "shorthand_property_identifier_pattern",
                                    "identifier",
                                    "property_identifier",
                                }:
                                    add_record(package, _node_text(child, source_bytes), child)
                        else:
                            add_record(package, "default", target)

            elif node.type == "call_expression":
                callee = node.children[0] if node.children else None
                args = _first_child_of_type(node, "arguments")
                if callee is None or args is None:
                    pass
                elif callee.type == "import" or _node_text(callee, source_bytes) == "import":
                    first_arg = None
                    for child in args.children:
                        if child.type not in {"(", ")", ","}:
                            first_arg = child
                            break
                    if first_arg is None:
                        return
                    specifier = _string_value(first_arg, source_bytes)
                    if specifier is None:
                        add_unresolved("dynamic_require", None, node)
                        return
                    package = _package_from_specifier(specifier, lookup)
                    if package:
                        add_record(package, "*", node)
                elif _node_text(callee, source_bytes) == "require":
                    first_arg = None
                    for child in args.children:
                        if child.type not in {"(", ")", ","}:
                            first_arg = child
                            break
                    if first_arg is not None and _string_value(first_arg, source_bytes) is None:
                        add_unresolved("dynamic_require", None, node)

            elif node.type == "export_statement":
                if "*" in _node_text(node, source_bytes):
                    module_node = _first_child_of_type(node, "string")
                    specifier = _string_value(module_node, source_bytes)
                    package = _package_from_specifier(specifier or "", lookup)
                    if package:
                        add_unresolved("reexport", package, node)

            elif node.type == "member_expression":
                left = node.children[0] if node.children else None
                if left is not None and left.type == "identifier":
                    alias = _node_text(left, source_bytes)
                    package = namespace_imports.get(alias)
                    if package:
                        add_unresolved("member_access", package, node)

            for child in node.children:
                visit(child)

        visit(tree.root_node)

    return UsageResult(records=records, unresolved=unresolved)
