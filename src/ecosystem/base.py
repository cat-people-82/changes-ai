from __future__ import annotations

import os
import shutil
import subprocess
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
    unresolved: list[dict]

    def packages_used(self) -> set[str]:
        return {record.package for record in self.records}

    def packages_with_flags(self) -> set[str]:
        packages: set[str] = set()
        for item in self.unresolved:
            if isinstance(item, dict):
                package = item.get("package")
            else:
                package = getattr(item, "package", None)
            if package:
                packages.add(package)
        return packages


@dataclass
class ManifestInfo:
    path: Path
    file_type: str
    has_lockfile: bool
    lockfile_path: Path | None
    lockfile_type: str | None


@dataclass
class ApplyOutcome:
    success: bool
    output: str
    files_modified: list[Path] = field(default_factory=list)


class EcosystemAdapter(Protocol):
    """Contract every ecosystem implementation satisfies."""

    name: str
    osv_ecosystem: str

    def manifest_candidates(self) -> list[tuple[str, str]]: ...

    def find_manifest(self, source: Path) -> ManifestInfo | None: ...

    def parse_manifest(
        self, content: str, file_type: str
    ) -> dict[str, str | None]: ...

    def discover_installed(self, source: Path) -> dict[str, str] | None: ...

    def fetch_currency(self, packages: list[str], cache) -> list[CurrencyRecord]: ...

    def build_graph(
        self,
        packages: dict[str, str | None],
        installed: dict[str, str] | None,
        cache,
        *,
        include_transitive: bool,
    ) -> list[GraphEdge]: ...

    def analyse_usage(
        self, source: Path, packages: dict[str, str | None]
    ) -> UsageResult: ...

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


def atomic_write(path: Path, content: str) -> None:
    """Write content atomically via a .tmp file then os.replace."""
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    os.replace(tmp_path, path)


def run_lock_tool(
    tool: str,
    args: list[str],
    manifest: ManifestInfo,
    *,
    missing_tool_hint: str | None = None,
) -> ApplyOutcome:
    """Run a lockfile-regeneration tool and return an ApplyOutcome.

    If the tool is not on PATH, returns a clear failure rather than raising.
    *missing_tool_hint* customises the "run X manually" suggestion in the
    error message; defaults to ``'<tool> install'``.
    """
    if shutil.which(tool) is None:
        hint = missing_tool_hint or f"{tool} install"
        return ApplyOutcome(
            success=False,
            output=(
                f"{tool} not found on PATH. Install {tool} or run "
                f"'{hint}' manually before deploying."
            ),
            files_modified=[],
        )
    result = subprocess.run(
        [tool, *args],
        cwd=manifest.path.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ApplyOutcome(
            success=False,
            output=(
                result.stderr or result.stdout or f"{tool} exited {result.returncode}"
            ).strip(),
            files_modified=[],
        )
    return ApplyOutcome(
        success=True,
        output=(result.stdout or "") + (result.stderr or ""),
        files_modified=[manifest.lockfile_path] if manifest.lockfile_path else [],
    )
