# Changes AI v0.7 — Part 1 of 4

## Ecosystem Adapter Protocol & Python Migration

This is part 1 of the v0.7 release. v0.7 ships three intertwined features
across four sequential parts:

- **Part 1 (this document):** Ecosystem adapter protocol + migrate existing
  Python logic behind it. Foundation work — no new user-visible features.
- **Part 2:** OSV per-ecosystem routing + ecosystem-agnostic apply pipeline
  for Python.
- **Part 3:** NPM adapter (parsers, currency, graph, install) + JS/TS usage
  analyser.
- **Part 4:** Interactive remediation editor + CLI wiring for `--apply` /
  `--auto-apply` / `--ecosystem`.

**Do not start Part 2 until Part 1 is complete and the test suite passes
unchanged.**

---

## Goal of Part 1

Define a uniform `EcosystemAdapter` protocol and route the existing Python
pipeline through it. After this part, `changes-ai` behaves identically to
v0.6 from a user's perspective. Internally, every ecosystem-specific
operation goes through the adapter, so adding a second ecosystem (Part 3)
becomes a localised change rather than a sweep through `changes_ai.py`.

---

## Context

Read these files before writing any plan or code:

- `src/changes_ai.py` — focus on `DEPENDENCY_CANDIDATES` (~85),
  `DependencyParser` (~186), `VenvParser` (~403), `find_venv` (~479),
  `LibrariesIOClient` (~580), `main()` package discovery (~1955).
- `src/usage.py` — Python AST analyser; the `analyse_project` function
  becomes the body of `PythonAdapter.analyse_usage`.
- `src/graph.py` — `build_dependency_edges` becomes the body of
  `PythonAdapter.build_graph`.
- `src/vulnerability.py` — note where `"PyPI"` is hardcoded (lines ~125,
  374). Do **not** modify these in this part — they are addressed in Part 2.
- `tests/test_smoke.py` — existing coverage. The migration must not break
  any of these tests.
- `pyproject.toml`.

---

## Constraints

- New modules go in `src/ecosystem/`. New tests go in `tests/test_smoke.py`.
- All new tests must be deterministic. No network calls, no LLM calls.
- All existing tests must continue to pass without modification.
- The adapter abstraction is internal. v0.6 CLI flags and behaviour are
  unchanged in this part.
- All changes must pass `pytest tests/` before this part is marked done.

---

## Task 1.1 — Ecosystem adapter protocol

**File:** `src/ecosystem/base.py` (new)

Define the protocol every ecosystem implements. Use `typing.Protocol` so
existing code paths can migrate incrementally and tests can supply mocks
without inheritance.

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class Package:
    name: str
    installed_version: str | None
    declared_constraint: str | None


@dataclass
class GraphEdge:
    parent: str
    child: str
    constraint: str | None = None


@dataclass
class CurrencyRecord:
    package: str
    installed_version: str | None
    latest_version: str | None
    latest_release_date: str | None
    release_cadence_days: float | None
    deprecated: bool
    signals: list[str] = field(default_factory=list)


@dataclass
class UsageRecord:
    package: str
    symbol: str
    source_file: str
    line: int


@dataclass
class UsageResult:
    records: list[UsageRecord]
    unresolved: list[dict]   # {"flag": str, "package": str|None, "source_file": str, "line": int}


@dataclass
class ManifestInfo:
    path: Path
    file_type: str           # adapter-specific: "pip" | "pyproject" | "package_json" | ...
    has_lockfile: bool
    lockfile_path: Path | None
    lockfile_type: str | None  # adapter-specific


@dataclass
class ApplyOutcome:
    success: bool
    output: str
    files_modified: list[Path] = field(default_factory=list)


class EcosystemAdapter(Protocol):
    """Contract every ecosystem implementation satisfies.

    Methods are grouped by lifecycle phase: discovery, currency,
    dependency-graph construction, usage analysis, and apply. The apply
    methods are exercised in Part 2 (Python) and Part 3 (NPM); leave them
    callable but allow them to raise NotImplementedError in Part 1.
    """

    name: str            # "python" | "npm"
    osv_ecosystem: str   # "PyPI"  | "npm"

    # --- Discovery -------------------------------------------------------
    def manifest_candidates(self) -> list[tuple[str, str]]: ...
    def find_manifest(self, source: Path) -> ManifestInfo | None: ...
    def parse_manifest(self, content: str, file_type: str) -> dict[str, str | None]: ...
    def discover_installed(self, source: Path) -> dict[str, str] | None: ...

    # --- Currency / metadata --------------------------------------------
    def fetch_currency(self, packages: list[str], cache) -> list[CurrencyRecord]: ...

    # --- Dependency graph -----------------------------------------------
    def build_graph(
        self,
        packages: dict[str, str | None],
        installed: dict[str, str] | None,
        cache,
        *,
        include_transitive: bool,
    ) -> list[GraphEdge]: ...

    # --- Usage analysis -------------------------------------------------
    def analyse_usage(self, source: Path, packages: dict) -> UsageResult: ...

    # --- Apply (implemented in Parts 2 and 3) ---------------------------
    def write_manifest(
        self,
        manifest: ManifestInfo,
        upgrades: list,
        original_content: str,
    ) -> Path: ...

    def regenerate_lockfile(self, manifest: ManifestInfo) -> ApplyOutcome: ...

    def install(
        self,
        manifest: ManifestInfo,
        upgrades: list,
        environment_root: Path | None,
    ) -> ApplyOutcome: ...

    def dry_run_validate(
        self,
        manifest: ManifestInfo,
        upgrades: list,
        environment_root: Path | None,
    ) -> tuple[bool, str]: ...
```

**Registration:** `src/ecosystem/__init__.py`:

```python
from pathlib import Path
from .base import (
    EcosystemAdapter,
    Package,
    GraphEdge,
    CurrencyRecord,
    UsageRecord,
    UsageResult,
    ManifestInfo,
    ApplyOutcome,
)
from .python_adapter import PythonAdapter

REGISTRY: dict[str, EcosystemAdapter] = {
    "python": PythonAdapter(),
}


def detect_adapter(source: Path) -> EcosystemAdapter | None:
    """Return the adapter whose manifest candidates match files in source.

    When multiple adapters match, prefer the one whose manifest is at the
    repo root. If multiple match at the root, return the first by registry
    order.
    """
    for adapter in REGISTRY.values():
        if adapter.find_manifest(source) is not None:
            return adapter
    return None
```

`NpmAdapter` is added to the registry in Part 3. Until then `REGISTRY`
contains only `"python"`.

**Tests:**

- `test_ecosystem_protocol_satisfied_by_python_adapter` — instantiate
  `PythonAdapter()`, assert all protocol attributes are callable and the
  dataclass shapes are correct.
- `test_detect_adapter_finds_python_for_pyproject_only` —
  `tmp_path` containing only `pyproject.toml`, assert
  `detect_adapter` returns the Python adapter.
- `test_detect_adapter_returns_none_for_empty_directory` — empty
  `tmp_path`, assert `None`.

---

## Task 1.2 — Migrate Python logic behind PythonAdapter

**File:** `src/ecosystem/python_adapter.py` (new)

This task moves logic; it does not change behaviour. After this task the
test suite must still pass without modifications to existing tests.

`PythonAdapter` wraps `DependencyParser`, `VenvParser`, the libraries.io
currency code, the existing graph builder, and `usage.py`. The
implementation is mostly delegation:

```python
from __future__ import annotations
from pathlib import Path

from src.changes_ai import (
    DependencyParser,
    VenvParser,
    find_venv,
    DEPENDENCY_CANDIDATES,
    LibrariesIOClient,
)
from src.usage import analyse_project as _python_analyse_usage
from src.graph import build_dependency_edges as _python_build_edges

from .base import (
    EcosystemAdapter,
    ManifestInfo,
    ApplyOutcome,
    UsageResult,
    UsageRecord,
    CurrencyRecord,
    GraphEdge,
)


PYTHON_LOCKFILE_CANDIDATES = [
    ("uv.lock", "uv_lockfile"),
    ("poetry.lock", "poetry_lockfile"),
]


class PythonAdapter:
    name = "python"
    osv_ecosystem = "PyPI"

    # --- Discovery -------------------------------------------------------

    def manifest_candidates(self):
        return list(DEPENDENCY_CANDIDATES)

    def find_manifest(self, source: Path) -> ManifestInfo | None:
        for rel_path, file_type in DEPENDENCY_CANDIDATES:
            candidate = source / rel_path
            if candidate.is_file():
                lockfile_path, lockfile_type = self._detect_lockfile(source)
                return ManifestInfo(
                    path=candidate,
                    file_type=file_type,
                    has_lockfile=lockfile_path is not None,
                    lockfile_path=lockfile_path,
                    lockfile_type=lockfile_type,
                )
        return None

    def _detect_lockfile(self, source: Path) -> tuple[Path | None, str | None]:
        for rel_path, lock_type in PYTHON_LOCKFILE_CANDIDATES:
            candidate = source / rel_path
            if candidate.is_file():
                return candidate, lock_type
        return None, None

    def parse_manifest(self, content: str, file_type: str) -> dict:
        return DependencyParser.parse(content, file_type)

    def discover_installed(self, source: Path) -> dict | None:
        try:
            venv = find_venv(source)
        except FileNotFoundError:
            return None
        return VenvParser.parse(venv)

    # --- Currency / metadata --------------------------------------------

    def fetch_currency(self, packages: list[str], cache) -> list[CurrencyRecord]:
        """Wrap the existing libraries.io currency code in CurrencyRecord."""
        client = LibrariesIOClient(cache=cache)
        records: list[CurrencyRecord] = []
        for package in packages:
            raw = client.fetch_currency(package)  # match existing call signature
            if raw is None:
                continue
            records.append(
                CurrencyRecord(
                    package=raw["package"],
                    installed_version=raw.get("installed_version"),
                    latest_version=raw.get("latest_version"),
                    latest_release_date=raw.get("latest_release_date"),
                    release_cadence_days=raw.get("release_cadence_days"),
                    deprecated=raw.get("deprecated", False),
                    signals=raw.get("signals", []),
                )
            )
        return records

    # --- Dependency graph -----------------------------------------------

    def build_graph(
        self,
        packages: dict,
        installed: dict | None,
        cache,
        *,
        include_transitive: bool,
    ) -> list[GraphEdge]:
        client = LibrariesIOClient(cache=cache) if include_transitive else None
        edges = _python_build_edges(
            packages,
            project_node=self._project_node(packages),
            installed_versions=installed,
            libraries_client=client,
            include_transitive=include_transitive,
        )
        return [
            GraphEdge(parent=e["parent"], child=e["child"]) for e in edges
        ]

    @staticmethod
    def _project_node(packages: dict) -> str:
        return "project"

    # --- Usage analysis -------------------------------------------------

    def analyse_usage(self, source: Path, packages: dict) -> UsageResult:
        raw = _python_analyse_usage(source, packages=packages)
        records = [
            UsageRecord(
                package=r["package"],
                symbol=r["symbol"],
                source_file=r["source_file"],
                line=r["line"],
            )
            for r in raw.get("records", [])
        ]
        return UsageResult(records=records, unresolved=raw.get("unresolved", []))

    # --- Apply (Part 2) -------------------------------------------------

    def write_manifest(self, manifest, upgrades, original_content):
        raise NotImplementedError("PythonAdapter.write_manifest lands in Part 2")

    def regenerate_lockfile(self, manifest):
        raise NotImplementedError("PythonAdapter.regenerate_lockfile lands in Part 2")

    def install(self, manifest, upgrades, environment_root):
        raise NotImplementedError("PythonAdapter.install lands in Part 2")

    def dry_run_validate(self, manifest, upgrades, environment_root):
        raise NotImplementedError("PythonAdapter.dry_run_validate lands in Part 2")
```

> **Note on call signatures:** the wrappers above use placeholder shapes
> (`client.fetch_currency`, `_python_analyse_usage(source, packages=...)`).
> Inspect the actual function signatures in `changes_ai.py`, `graph.py`,
> and `usage.py` and adapt the wrappers to call them correctly. Do not
> modify the underlying functions.

**Wiring in `src/changes_ai.py`:** Refactor `main()` so every
ecosystem-specific call goes through the adapter:

- After `source_path` is resolved, add:
  ```python
  from .ecosystem import detect_adapter
  adapter = detect_adapter(source_path)
  if adapter is None:
      print(
          f"Error: no supported ecosystem detected in {source_path}.",
          file=sys.stderr,
      )
      sys.exit(1)
  ```
- Replace the `for rel_path, file_type in DEPENDENCY_CANDIDATES` discovery
  loop with `manifest_info = adapter.find_manifest(source_path)` and the
  ecosystem-specific code paths it controls.
- Replace `DependencyParser.parse(content, file_type)` with
  `adapter.parse_manifest(content, file_type)`.
- Replace `VenvParser.parse(venv_path)` with
  `adapter.discover_installed(source_path)`.
- Replace direct `usage.analyse_project(...)` with
  `adapter.analyse_usage(...)`.
- Replace direct `build_dependency_edges(...)` with
  `adapter.build_graph(...)`.

Keep the existing public functions exported from their current modules.
The adapter delegates to them so the existing test surface area is
preserved.

**Do not** modify the OSV client's hardcoded `"PyPI"` references in this
part — Part 2 handles that.

**Tests:** No new tests required for this task. Existing tests in
`tests/test_smoke.py` must continue to pass without modification. If any
existing test breaks, the migration is incorrect — fix the migration, not
the test.

---

## Definition of Done — Part 1

- [ ] `pytest tests/` passes with zero failures and zero errors.
- [ ] `changes-ai --version` works from a clean `pip install -e .`.
- [ ] All v0.6 CLI flags behave identically. A user running
  `changes-ai --source <py-project> --all` sees no behaviour change.
- [ ] `src/ecosystem/base.py`, `src/ecosystem/__init__.py`, and
  `src/ecosystem/python_adapter.py` exist and import cleanly.
- [ ] `from src.ecosystem import REGISTRY, detect_adapter, PythonAdapter`
  succeeds in a Python REPL.
- [ ] `main()` in `src/changes_ai.py` no longer references
  `DEPENDENCY_CANDIDATES`, `DependencyParser.parse`, `VenvParser.parse`,
  `usage.analyse_project`, or `build_dependency_edges` directly. All those
  calls go through `adapter.*`.
- [ ] No CHANGELOG entry yet — Part 4 writes the consolidated v0.7.0 entry.
