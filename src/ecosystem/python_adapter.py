from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from ..changes_ai import (
    DEPENDENCY_CANDIDATES,
    DependencyParser,
    LibrariesIOClient,
    VenvParser,
    find_venv,
)
from ..currency import analyse_currency as _analyse_currency
from ..graph import build_dependency_edges as _python_build_edges
from ..usage import analyse_usage as _python_analyse_usage
from .base import ApplyOutcome, CurrencyRecord, ManifestInfo, atomic_write, run_lock_tool

PYTHON_LOCKFILE_CANDIDATES = [
    ("uv.lock", "uv_lockfile"),
    ("poetry.lock", "poetry_lockfile"),
]


class PythonAdapter:
    name = "python"
    osv_ecosystem = "PyPI"

    def manifest_candidates(self) -> list[tuple[str, str]]:
        return list(DEPENDENCY_CANDIDATES)

    def find_manifest(self, source: Path) -> ManifestInfo | None:
        source = Path(source)
        lockfile_path, lockfile_type = self._detect_lockfile(source)
        first_match: ManifestInfo | None = None
        for rel_path, file_type in DEPENDENCY_CANDIDATES:
            candidate = source / rel_path
            if not candidate.is_file():
                continue
            manifest = ManifestInfo(
                path=candidate,
                file_type=file_type,
                has_lockfile=lockfile_path is not None,
                lockfile_path=lockfile_path,
                lockfile_type=lockfile_type,
            )
            if first_match is None:
                first_match = manifest
            try:
                content = candidate.read_text(encoding="utf-8")
            except OSError:
                return manifest
            if self.parse_manifest(content, file_type):
                return manifest
        return first_match

    def _detect_lockfile(self, source: Path) -> tuple[Path | None, str | None]:
        for rel_path, lockfile_type in PYTHON_LOCKFILE_CANDIDATES:
            candidate = source / rel_path
            if candidate.is_file():
                return candidate, lockfile_type
        return None, None

    def parse_manifest(
        self, content: str, file_type: str
    ) -> dict[str, str | None]:
        return DependencyParser.parse(content, file_type)

    def discover_installed(self, source: Path) -> dict[str, str] | None:
        try:
            venv_path = find_venv(source)
        except FileNotFoundError:
            return None
        return VenvParser.parse(venv_path)

    def fetch_currency(self, packages: list[str], cache) -> list[CurrencyRecord]:
        client = LibrariesIOClient(cache=cache)
        mapping = [
            {
                "name": package,
                "installed": "(unknown)",
                "latest": client.get_latest_version(package) or "(unknown)",
            }
            for package in packages
        ]
        raw_records = _analyse_currency(mapping, client)
        return [
            CurrencyRecord(
                package=record.get("package") or "",
                installed_version=record.get("installed_version"),
                latest_version=record.get("latest_version"),
                latest_release_date=record.get("latest_release_date"),
                release_cadence_days=record.get("release_cadence_days"),
                deprecated=bool(record.get("is_deprecated", False)),
                signals=list(record.get("signals") or []),
            )
            for record in raw_records
        ]

    def build_graph(
        self,
        packages: dict[str, str | None],
        installed: dict[str, str] | None,
        cache,
        *,
        include_transitive: bool,
    ):
        client = None
        if include_transitive:
            if isinstance(cache, LibrariesIOClient):
                client = cache
            else:
                client = LibrariesIOClient(cache=cache)
        return _python_build_edges(
            packages,
            project_node="project",
            installed_versions=installed,
            libraries_client=client,
            include_transitive=include_transitive,
        )

    def analyse_usage(self, source: Path, packages: dict[str, str | None]):
        try:
            venv_path = find_venv(source)
        except FileNotFoundError:
            venv_path = None
        return _python_analyse_usage(source, packages, venv_path=venv_path)

    def write_manifest(self, manifest, upgrades, original_content) -> Path:
        if manifest.file_type == "pip":
            rewritten = self._write_requirements_txt(original_content, upgrades)
        elif manifest.file_type == "pyproject":
            rewritten = self._write_pyproject_toml(original_content, upgrades)
        else:
            raise ValueError(f"unsupported manifest type for apply: {manifest.file_type}")
        atomic_write(manifest.path, rewritten)
        return manifest.path

    def regenerate_lockfile(self, manifest: ManifestInfo) -> ApplyOutcome:
        if not manifest.has_lockfile or manifest.lockfile_type is None:
            return ApplyOutcome(
                success=True,
                output="no lockfile present",
                files_modified=[],
            )
        if manifest.lockfile_type == "uv_lockfile":
            return run_lock_tool(
                "uv",
                ["lock"],
                manifest,
                missing_tool_hint="uv lock",
            )
        if manifest.lockfile_type == "poetry_lockfile":
            return run_lock_tool(
                "poetry",
                ["lock", "--no-update"],
                manifest,
                missing_tool_hint="poetry lock",
            )
        return ApplyOutcome(
            success=False,
            output=f"unknown lockfile type: {manifest.lockfile_type}",
            files_modified=[],
        )

    def install(
        self,
        manifest: ManifestInfo,
        upgrades: list,
        environment_root: Path | None,
    ) -> ApplyOutcome:
        pip_cmd = self._resolve_pip(environment_root)
        if not pip_cmd:
            return ApplyOutcome(
                success=False,
                output="pip not found on PATH or in venv",
                files_modified=[],
            )
        pkg_args = [f"{u.package}=={u.to_version}" for u in upgrades]
        result = subprocess.run(
            pip_cmd + ["install", *pkg_args],
            capture_output=True,
            text=True,
            check=False,
        )
        return ApplyOutcome(
            success=(result.returncode == 0),
            output=(result.stdout or "") + (result.stderr or ""),
            files_modified=[],
        )

    def dry_run_validate(
        self,
        manifest: ManifestInfo,
        upgrades: list,
        environment_root: Path | None,
    ) -> tuple[bool, str]:
        pip_cmd = self._resolve_pip(environment_root)
        if not pip_cmd:
            return False, "pip not found on PATH or in venv"
        pkg_args = [f"{u.package}=={u.to_version}" for u in upgrades]
        result = subprocess.run(
            pip_cmd + ["install", "--dry-run", "--no-deps", *pkg_args],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return (
                False,
                (result.stderr or result.stdout or "pip dry-run failed").strip(),
            )
        return True, ""

    @staticmethod
    def _normalise_package_name(name: str) -> str:
        return name.lower().replace("_", "-")

    def _write_requirements_txt(self, content: str, upgrades: list) -> str:
        upgrade_map = {
            self._normalise_package_name(upgrade.package): upgrade.to_version
            for upgrade in upgrades
        }
        rewritten: list[str] = []
        for line in content.splitlines(keepends=True):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                rewritten.append(line)
                continue
            rewritten.append(self._rewrite_requirement_line(line, upgrade_map))
        return "".join(rewritten)

    def _write_pyproject_toml(self, content: str, upgrades: list) -> str:
        upgrade_map = {
            self._normalise_package_name(upgrade.package): upgrade.to_version
            for upgrade in upgrades
        }
        rewritten: list[str] = []
        current_section = ""
        in_project_dependencies = False

        for line in content.splitlines(keepends=True):
            section_match = re.match(r"^\s*\[([^\]]+)\]\s*$", line)
            if section_match:
                current_section = section_match.group(1).strip()
                in_project_dependencies = False
                rewritten.append(line)
                continue

            if current_section == "project" and re.match(r"^\s*dependencies\s*=\s*\[\s*$", line):
                in_project_dependencies = True
                rewritten.append(line)
                continue

            if in_project_dependencies:
                rewritten.append(self._rewrite_pep621_dependency_line(line, upgrade_map))
                if "]" in line:
                    in_project_dependencies = False
                continue

            if current_section == "tool.poetry.dependencies":
                rewritten.append(self._rewrite_poetry_dependency_line(line, upgrade_map))
                continue

            rewritten.append(line)
        return "".join(rewritten)

    def _rewrite_requirement_line(
        self,
        line: str,
        upgrade_map: dict[str, str],
    ) -> str:
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        comment_match = re.match(r"^(.*?)(\s+#.*)?$", body)
        if comment_match is None:
            return line
        requirement_part = comment_match.group(1) or ""
        comment = comment_match.group(2) or ""
        base_part, marker_part = self._split_marker(requirement_part)
        req_match = re.match(
            r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*.*)$",
            base_part,
        )
        if req_match is None:
            return line
        indent, package, extras, _rest = req_match.groups()
        version = upgrade_map.get(self._normalise_package_name(package))
        if version is None:
            return line
        rewritten = (
            f"{indent}{package}{extras or ''}=={version}{marker_part}{comment}{newline}"
        )
        return rewritten

    def _rewrite_pep621_dependency_line(
        self,
        line: str,
        upgrade_map: dict[str, str],
    ) -> str:
        match = re.match(
            r'^(\s*)(["\'])([^"\']+)(["\'])(\s*,?\s*)(#.*)?(\n?)$',
            line,
        )
        if match is None:
            return line
        indent, quote, requirement, _quote2, suffix, comment, newline = match.groups()
        rewritten_requirement = self._rewrite_requirement_string(requirement, upgrade_map)
        if rewritten_requirement == requirement:
            return line
        return (
            f"{indent}{quote}{rewritten_requirement}{quote}{suffix}{comment or ''}{newline}"
        )

    def _rewrite_poetry_dependency_line(
        self,
        line: str,
        upgrade_map: dict[str, str],
    ) -> str:
        inline_table_match = re.match(
            r'^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*=\s*\{.*?\bversion\s*=\s*)(["\'])([^"\']*)(["\'])(.*\}\s*)(#.*)?(\n?)$',
            line,
        )
        if inline_table_match is not None:
            (
                indent,
                package,
                prefix,
                quote,
                _version,
                _quote2,
                suffix,
                comment,
                newline,
            ) = inline_table_match.groups()
            new_version = upgrade_map.get(self._normalise_package_name(package))
            if new_version is None:
                return line
            return (
                f"{indent}{package}{prefix}{quote}=={new_version}{quote}"
                f"{suffix}{comment or ''}{newline}"
            )

        string_match = re.match(
            r'^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*=\s*)(["\'])([^"\']*)(["\'])(\s*)(#.*)?(\n?)$',
            line,
        )
        if string_match is None:
            return line
        indent, package, sep, quote, _version, _quote2, spacing, comment, newline = (
            string_match.groups()
        )
        new_version = upgrade_map.get(self._normalise_package_name(package))
        if new_version is None:
            return line
        return (
            f"{indent}{package}{sep}{quote}=={new_version}{quote}"
            f"{spacing}{comment or ''}{newline}"
        )

    def _rewrite_requirement_string(
        self,
        requirement: str,
        upgrade_map: dict[str, str],
    ) -> str:
        parsed = DependencyParser._parse_requirement_entry(requirement)
        if parsed is None:
            return requirement
        package, _specifier = parsed
        new_version = upgrade_map.get(self._normalise_package_name(package))
        if new_version is None:
            return requirement

        marker_index = requirement.find(";")
        if marker_index == -1:
            marker_part = ""
            requirement_part = requirement
        else:
            marker_part = requirement[marker_index:]
            requirement_part = requirement[:marker_index]

        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?.*$",
            requirement_part.strip(),
        )
        if match is None:
            return requirement
        package_name, extras = match.groups()
        return f"{package_name}{extras or ''}=={new_version}{marker_part}"

    @staticmethod
    def _split_marker(requirement_part: str) -> tuple[str, str]:
        marker_index = requirement_part.find(";")
        if marker_index == -1:
            return requirement_part, ""
        return requirement_part[:marker_index], requirement_part[marker_index:]

    @staticmethod
    def _resolve_pip(environment_root: Path | None) -> list[str] | None:
        if environment_root is not None:
            bin_dir = environment_root / "bin"
            uv = bin_dir / "uv"
            if uv.exists():
                return [str(uv), "pip"]
            pip = bin_dir / "pip"
            if pip.exists():
                return [str(pip)]
        fallback = shutil.which("pip")
        return [fallback] if fallback else None
