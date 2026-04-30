from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

from ..changes_ai import LibrariesIOClient
from ..usage import _normalise as _python_normalise
from .base import ApplyOutcome, CurrencyRecord, GraphEdge, ManifestInfo, atomic_write, run_lock_tool

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

NPM_DEPENDENCY_CANDIDATES = [
    ("package.json", "package_json"),
]

NPM_LOCKFILE_CANDIDATES = [
    ("package-lock.json", "npm_lockfile"),
    ("yarn.lock", "yarn_lockfile"),
    ("pnpm-lock.yaml", "pnpm_lockfile"),
]

_NPM_DEP_SECTIONS = (
    "dependencies",
    "peerDependencies",
    "optionalDependencies",
    "devDependencies",
)
_NPM_DEP_PRIORITY = {
    "dependencies": 0,
    "peerDependencies": 1,
    "optionalDependencies": 2,
    "devDependencies": 3,
}


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalise_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _descriptor_to_package_name(descriptor: str) -> str:
    descriptor = descriptor.strip().strip('"').strip("'")
    if descriptor.startswith("@"):
        slash = descriptor.find("/")
        if slash == -1:
            return descriptor
        at_after_name = descriptor.find("@", slash + 1)
        if at_after_name == -1:
            return descriptor
        return descriptor[:at_after_name]
    return descriptor.split("@", 1)[0]


def _pnpm_key_to_name_version(key: str) -> tuple[str | None, str | None]:
    cleaned = key.strip()
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    cleaned = cleaned.split("(", 1)[0]
    if "@" not in cleaned:
        return None, None
    name, version = cleaned.rsplit("@", 1)
    return name or None, version or None


class NpmRegistryClient:
    BASE_URL = "https://registry.npmjs.org"

    def __init__(self, cache=None, refresh: bool = False, offline: bool = False):
        self.cache = cache
        self.refresh = refresh
        self.offline = offline
        self.session = requests.Session()
        self.fallback = LibrariesIOClient(
            cache=cache,
            refresh=refresh,
            offline=offline,
        )

    def fetch_metadata(self, package: str) -> dict | None:
        cache_key = package.lower()
        if self.cache is not None:
            cached = self.cache.get(
                "npm_registry_package",
                cache_key,
                refresh=self.refresh,
                offline=self.offline,
            )
            if cached is not None:
                return cached

        url = f"{self.BASE_URL}/{quote(package, safe='')}"
        try:
            response = self.session.get(url, timeout=30)
        except requests.RequestException as exc:
            _warn(f"npm registry request failed for {package}: {exc}")
            return self.fallback.get_package_info(package, platform="npm")

        if response.status_code == 404:
            return self.fallback.get_package_info(package, platform="npm")
        if response.status_code != 200:
            _warn(f"npm registry returned HTTP {response.status_code} for {package}")
            return self.fallback.get_package_info(package, platform="npm")

        try:
            payload = response.json()
        except ValueError as exc:
            _warn(f"npm registry returned invalid JSON for {package}: {exc}")
            return self.fallback.get_package_info(package, platform="npm")

        if self.cache is not None:
            self.cache.set(
                "npm_registry_package",
                cache_key,
                payload,
                ttl_seconds=6 * 3600,
            )
        return payload

    def head_version_exists(self, package: str, version: str) -> bool:
        cache_key = f"{package.lower()}@{version}"
        if self.cache is not None:
            cached = self.cache.get(
                "npm_registry_head",
                cache_key,
                refresh=self.refresh,
                offline=self.offline,
            )
            if cached is not None:
                return bool(cached.get("exists"))

        url = f"{self.BASE_URL}/{quote(package, safe='')}/{quote(version, safe='')}"
        try:
            response = self.session.head(url, timeout=30)
        except requests.RequestException:
            return False
        exists = response.status_code == 200
        if self.cache is not None:
            self.cache.set(
                "npm_registry_head",
                cache_key,
                {"exists": exists},
                ttl_seconds=3600,
            )
        return exists


class NpmAdapter:
    name = "npm"
    osv_ecosystem = "npm"

    def __init__(self) -> None:
        self._last_manifest: ManifestInfo | None = None
        self._last_installed: dict[str, str] | None = None

    def manifest_candidates(self) -> list[tuple[str, str]]:
        return list(NPM_DEPENDENCY_CANDIDATES)

    def find_manifest(self, source: Path) -> ManifestInfo | None:
        source = Path(source)
        for rel_path, file_type in NPM_DEPENDENCY_CANDIDATES:
            candidate = source / rel_path
            if candidate.is_file():
                lockfile_path, lockfile_type = self._detect_lockfile(source)
                self._last_manifest = ManifestInfo(
                    path=candidate,
                    file_type=file_type,
                    has_lockfile=lockfile_path is not None,
                    lockfile_path=lockfile_path,
                    lockfile_type=lockfile_type,
                )
                return self._last_manifest
        self._last_manifest = None
        return None

    def _detect_lockfile(self, source: Path) -> tuple[Path | None, str | None]:
        for rel_path, lockfile_type in NPM_LOCKFILE_CANDIDATES:
            candidate = source / rel_path
            if candidate.is_file():
                return candidate, lockfile_type
        return None, None

    def parse_manifest(
        self, content: str, file_type: str
    ) -> dict[str, str | None]:
        if file_type != "package_json":
            raise ValueError(f"unsupported manifest type: {file_type}")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid package.json at line {exc.lineno}: {exc.msg}"
            ) from exc

        ordered: list[tuple[str, str | None, int]] = []
        seen: dict[str, tuple[str, str | None, int]] = {}
        for section in _NPM_DEP_SECTIONS:
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, constraint in deps.items():
                if not isinstance(name, str):
                    continue
                if not isinstance(constraint, str):
                    constraint = None
                rank = _NPM_DEP_PRIORITY[section]
                existing = seen.get(name)
                if existing is None or rank < existing[2]:
                    seen[name] = (name, constraint, rank)

        ordered = sorted(seen.values(), key=lambda item: (item[2], item[0].lower()))
        return {name: constraint for name, constraint, _rank in ordered}

    @staticmethod
    def parse_npm_lockfile(content: str) -> dict[str, str]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            _warn(f"failed to parse package-lock.json: {exc}")
            return {}

        lockfile_version = data.get("lockfileVersion")
        if isinstance(lockfile_version, int) and lockfile_version >= 2:
            packages = data.get("packages")
            if not isinstance(packages, dict):
                return {}
            resolved: dict[str, str] = {}
            for path_key, entry in packages.items():
                if not path_key or not isinstance(entry, dict):
                    continue
                if "node_modules/" not in path_key:
                    continue
                name = path_key.rsplit("node_modules/", 1)[-1]
                version = entry.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    resolved[name] = version
            return resolved

        resolved: dict[str, str] = {}

        def walk(tree: dict) -> None:
            if not isinstance(tree, dict):
                return
            for name, entry in tree.items():
                if not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                if isinstance(version, str):
                    resolved[name] = version
                walk(entry.get("dependencies") or {})

        walk(data.get("dependencies") or {})
        return resolved

    @staticmethod
    def parse_yarn_lockfile(content: str) -> dict[str, str]:
        stripped = content.lstrip()
        if stripped.startswith("__metadata:"):
            if yaml is None:
                _warn("PyYAML not available for yarn.lock parsing")
                return {}
            try:
                data = yaml.safe_load(content) or {}
            except Exception as exc:  # noqa: BLE001
                _warn(f"failed to parse yarn.lock: {exc}")
                return {}
            resolved: dict[str, str] = {}
            for key, entry in data.items():
                if key == "__metadata" or not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                if not isinstance(version, str):
                    continue
                descriptor = str(key).split(",", 1)[0].strip()
                name = _descriptor_to_package_name(descriptor)
                if name:
                    resolved[name] = version
            return resolved

        resolved: dict[str, str] = {}
        current_names: list[str] = []
        current_version: str | None = None
        saw_block = False
        for line in content.splitlines():
            if not line.strip():
                continue
            if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
                if current_names and current_version:
                    for name in current_names:
                        resolved[name] = current_version
                saw_block = True
                current_version = None
                descriptors = line.rstrip(":")
                current_names = [
                    _descriptor_to_package_name(part.strip())
                    for part in descriptors.split(",")
                    if part.strip()
                ]
                continue
            stripped_line = line.strip()
            version_match = re.match(r'^version\s+"([^"]+)"$', stripped_line)
            if version_match:
                current_version = version_match.group(1)
        if current_names and current_version:
            for name in current_names:
                resolved[name] = current_version
        if not resolved and content.strip() and not saw_block:
            _warn("failed to parse yarn.lock: unsupported format")
        return resolved

    @staticmethod
    def parse_pnpm_lockfile(content: str) -> dict[str, str]:
        if yaml is None:
            _warn("PyYAML not available for pnpm-lock.yaml parsing")
            return {}
        try:
            data = yaml.safe_load(content) or {}
        except Exception as exc:  # noqa: BLE001
            _warn(f"failed to parse pnpm-lock.yaml: {exc}")
            return {}
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return {}
        resolved: dict[str, str] = {}
        for key in packages:
            name, version = _pnpm_key_to_name_version(str(key))
            if name and version:
                resolved[name] = version
        return resolved

    def discover_installed(self, source: Path) -> dict[str, str] | None:
        manifest = self.find_manifest(source)
        installed: dict[str, str] = {}
        if manifest and manifest.has_lockfile and manifest.lockfile_path is not None:
            try:
                content = manifest.lockfile_path.read_text(encoding="utf-8")
            except OSError:
                content = ""
            installed = self._parse_lockfile_versions(
                manifest.lockfile_type,
                content,
            )
        if not installed:
            installed = self._read_node_modules(Path(source))
        self._last_installed = installed or None
        return self._last_installed

    def fetch_currency(self, packages: list[str], cache) -> list[CurrencyRecord]:
        client = NpmRegistryClient(cache=cache)
        installed_lookup = self._last_installed or {}
        records: list[CurrencyRecord] = []
        now = datetime.now(timezone.utc)
        for package in packages:
            metadata = client.fetch_metadata(package)
            latest_version = None
            latest_release_date = None
            cadence = None
            deprecated = False
            signals: list[str] = []

            if metadata:
                latest_version = self._latest_npm_version(metadata)
                latest_release = self._latest_release_date(metadata, latest_version)
                latest_release_date = (
                    latest_release.isoformat().replace("+00:00", "Z")
                    if latest_release is not None
                    else None
                )
                cadence = self._release_cadence_days(metadata)
                deprecated = self._is_latest_deprecated(metadata, latest_version)
                if deprecated:
                    signals.append("deprecated")
                if latest_release is not None and (now - latest_release).days > 548:
                    signals.append("unmaintained")

            records.append(
                CurrencyRecord(
                    package=package,
                    installed_version=installed_lookup.get(package),
                    latest_version=latest_version,
                    latest_release_date=latest_release_date,
                    release_cadence_days=cadence,
                    deprecated=deprecated,
                    signals=signals,
                )
            )
        return records

    def build_graph(
        self,
        packages: dict[str, str | None],
        installed: dict[str, str] | None,
        cache,
        *,
        include_transitive: bool,
    ) -> list[GraphEdge]:
        manifest = self._last_manifest
        project_name = self._project_name(manifest) if manifest else "project"
        edges: list[GraphEdge] = [
            GraphEdge(parent=project_name, child=name) for name in packages
        ]
        if not include_transitive:
            return edges
        if manifest is None or not manifest.has_lockfile or manifest.lockfile_path is None:
            _warn("transitive npm dependency graph requires a lockfile; using direct dependencies only")
            return edges
        try:
            content = manifest.lockfile_path.read_text(encoding="utf-8")
        except OSError:
            return edges
        lock_edges = self._build_lockfile_edges(
            manifest.lockfile_type,
            content,
            project_name,
        )
        return lock_edges or edges

    def analyse_usage(self, source: Path, packages: dict):
        from .js_usage import analyse_project as _js_analyse

        return _js_analyse(source, packages=packages)

    def write_manifest(self, manifest, upgrades, original_content) -> Path:
        content = original_content
        for upgrade in upgrades:
            content = self._rewrite_package_json_dependency(
                content,
                upgrade.package,
                upgrade.to_version,
            )
        atomic_write(manifest.path, content)
        return manifest.path

    def regenerate_lockfile(self, manifest) -> ApplyOutcome:
        if not manifest.has_lockfile or manifest.lockfile_type is None:
            return ApplyOutcome(success=True, output="no lockfile present", files_modified=[])
        if manifest.lockfile_type == "npm_lockfile":
            return run_lock_tool(
                "npm",
                ["install", "--package-lock-only"],
                manifest,
                missing_tool_hint="npm install",
            )
        if manifest.lockfile_type == "yarn_lockfile":
            if manifest.lockfile_path is None:
                return ApplyOutcome(success=True, output="no lockfile path", files_modified=[])
            lock_content = manifest.lockfile_path.read_text(encoding="utf-8", errors="replace")
            if lock_content.lstrip().startswith("__metadata:"):
                return run_lock_tool(
                    "yarn",
                    ["install", "--mode=update-lockfile"],
                    manifest,
                    missing_tool_hint="yarn install",
                )
            return run_lock_tool(
                "yarn",
                ["install", "--frozen-lockfile=false"],
                manifest,
                missing_tool_hint="yarn install",
            )
        if manifest.lockfile_type == "pnpm_lockfile":
            return run_lock_tool(
                "pnpm",
                ["install", "--lockfile-only"],
                manifest,
                missing_tool_hint="pnpm install",
            )
        return ApplyOutcome(
            success=False,
            output=f"unknown lockfile type: {manifest.lockfile_type}",
            files_modified=[],
        )

    def install(self, manifest, upgrades, environment_root) -> ApplyOutcome:
        tool, args = self._install_command(manifest)
        if shutil.which(tool) is None:
            return ApplyOutcome(
                success=False,
                output=(
                    f"{tool} not found on PATH. Install {tool} or run "
                    f"'{tool} install' manually before deploying."
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
        return ApplyOutcome(
            success=result.returncode == 0,
            output=(result.stdout or "") + (result.stderr or ""),
            files_modified=[],
        )

    def dry_run_validate(self, manifest, upgrades, environment_root) -> tuple[bool, str]:
        client = NpmRegistryClient(
            cache=getattr(self, "_apply_cache", None),
            refresh=getattr(self, "_apply_refresh", False),
            offline=getattr(self, "_apply_offline", False),
        )
        manifest_content = manifest.path.read_text(encoding="utf-8", errors="replace")
        current = self.parse_manifest(manifest_content, manifest.file_type)
        proposed = dict(current)
        for upgrade in upgrades:
            if not client.head_version_exists(upgrade.package, upgrade.to_version):
                return (
                    False,
                    f"{upgrade.package}@{upgrade.to_version} not found in npm registry",
                )
            proposed[upgrade.package] = upgrade.to_version

        for upgrade in upgrades:
            metadata = client.fetch_metadata(upgrade.package) or {}
            version_info = (metadata.get("versions") or {}).get(upgrade.to_version, {})
            peer_deps = version_info.get("peerDependencies") or {}
            if not isinstance(peer_deps, dict):
                continue
            for peer_package, required_range in peer_deps.items():
                candidate_spec = proposed.get(peer_package)
                if not candidate_spec or not isinstance(required_range, str):
                    continue
                if not self._peer_satisfies(candidate_spec, required_range):
                    return (
                        False,
                        f"peer dependency conflict: {upgrade.package}@{upgrade.to_version} "
                        f"requires {peer_package}{required_range}, current selection has {candidate_spec}",
                    )
        return True, ""

    def _parse_lockfile_versions(
        self,
        lockfile_type: str | None,
        content: str,
    ) -> dict[str, str]:
        if lockfile_type == "npm_lockfile":
            return self.parse_npm_lockfile(content)
        if lockfile_type == "yarn_lockfile":
            return self.parse_yarn_lockfile(content)
        if lockfile_type == "pnpm_lockfile":
            return self.parse_pnpm_lockfile(content)
        return {}

    @staticmethod
    def _read_node_modules(source: Path) -> dict[str, str]:
        installed: dict[str, str] = {}
        node_modules = source / "node_modules"
        if not node_modules.is_dir():
            return installed
        for package_json in node_modules.glob("*/package.json"):
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            name = data.get("name")
            version = data.get("version")
            if isinstance(name, str) and isinstance(version, str):
                installed[name] = version
        for package_json in node_modules.glob("@*/*/package.json"):
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            name = data.get("name")
            version = data.get("version")
            if isinstance(name, str) and isinstance(version, str):
                installed[name] = version
        return installed

    @staticmethod
    def _latest_npm_version(metadata: dict) -> str | None:
        dist_tags = metadata.get("dist-tags") or {}
        latest = dist_tags.get("latest")
        return latest if isinstance(latest, str) else None

    @staticmethod
    def _latest_release_date(metadata: dict, latest_version: str | None) -> datetime | None:
        times = metadata.get("time") or {}
        if latest_version and isinstance(times.get(latest_version), str):
            return _parse_timestamp(times.get(latest_version))
        return None

    @staticmethod
    def _release_cadence_days(metadata: dict) -> float | None:
        times = metadata.get("time") or {}
        dates = [
            _parse_timestamp(value)
            for key, value in times.items()
            if key not in {"created", "modified"} and isinstance(value, str)
        ]
        cleaned = sorted([date for date in dates if date is not None])
        if len(cleaned) < 2:
            return None
        cleaned = cleaned[-10:]
        intervals = [
            (newer - older).total_seconds() / 86400.0
            for older, newer in zip(cleaned, cleaned[1:])
            if newer > older
        ]
        if not intervals:
            return None
        return round(sum(intervals) / len(intervals), 1)

    @staticmethod
    def _is_latest_deprecated(metadata: dict, latest_version: str | None) -> bool:
        if not latest_version:
            return False
        versions = metadata.get("versions") or {}
        version_data = versions.get(latest_version) or {}
        return bool(version_data.get("deprecated"))

    def _project_name(self, manifest: ManifestInfo | None) -> str:
        if manifest is None:
            return "project"
        try:
            data = json.loads(manifest.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "project"
        name = data.get("name")
        return name if isinstance(name, str) and name else "project"

    def _build_lockfile_edges(
        self,
        lockfile_type: str | None,
        content: str,
        project_name: str,
    ) -> list[GraphEdge]:
        if lockfile_type == "npm_lockfile":
            return self._build_package_lock_edges(content, project_name)
        if lockfile_type == "pnpm_lockfile":
            return self._build_pnpm_edges(content, project_name)
        if lockfile_type == "yarn_lockfile":
            return self._build_yarn_edges(content, project_name)
        return []

    def _build_package_lock_edges(self, content: str, project_name: str) -> list[GraphEdge]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        edges: set[tuple[str, str]] = set()
        lockfile_version = data.get("lockfileVersion")
        if isinstance(lockfile_version, int) and lockfile_version >= 2:
            packages = data.get("packages") or {}
            if not isinstance(packages, dict):
                return []
            root_entry = packages.get("") or {}
            for dep_name in (root_entry.get("dependencies") or {}).keys():
                edges.add((project_name, dep_name))
            for path_key, entry in packages.items():
                if not path_key or not isinstance(entry, dict):
                    continue
                parent = self._parent_name_from_node_modules_path(path_key, project_name)
                if parent is None:
                    continue
                for dep_name in (entry.get("dependencies") or {}).keys():
                    edges.add((parent, dep_name))
            return [GraphEdge(parent=parent, child=child) for parent, child in sorted(edges)]

        def walk(parent: str, dependencies: dict) -> None:
            if not isinstance(dependencies, dict):
                return
            for dep_name, entry in dependencies.items():
                edges.add((parent, dep_name))
                if isinstance(entry, dict):
                    walk(dep_name, entry.get("dependencies") or {})

        walk(project_name, data.get("dependencies") or {})
        return [GraphEdge(parent=parent, child=child) for parent, child in sorted(edges)]

    @staticmethod
    def _parent_name_from_node_modules_path(path_key: str, project_name: str) -> str | None:
        if "node_modules/" not in path_key:
            return None
        prefix, _sep, _suffix = path_key.rpartition("node_modules/")
        if "node_modules/" not in prefix:
            return project_name
        return prefix.rstrip("/").rsplit("node_modules/", 1)[-1]

    def _build_yarn_edges(self, content: str, project_name: str) -> list[GraphEdge]:
        edges: set[tuple[str, str]] = set()
        manifest = self._last_manifest
        if manifest is not None:
            try:
                root = self.parse_manifest(manifest.path.read_text(encoding="utf-8"), "package_json")
            except (OSError, ValueError):
                root = {}
            for dep_name in root:
                edges.add((project_name, dep_name))
        stripped = content.lstrip()
        if stripped.startswith("__metadata:") and yaml is not None:
            try:
                data = yaml.safe_load(content) or {}
            except Exception:  # noqa: BLE001
                return [GraphEdge(parent=parent, child=child) for parent, child in sorted(edges)]
            for key, entry in data.items():
                if key == "__metadata" or not isinstance(entry, dict):
                    continue
                parent = _descriptor_to_package_name(str(key).split(",", 1)[0])
                for dep_name in (entry.get("dependencies") or {}).keys():
                    edges.add((parent, dep_name))
        return [GraphEdge(parent=parent, child=child) for parent, child in sorted(edges)]

    def _build_pnpm_edges(self, content: str, project_name: str) -> list[GraphEdge]:
        if yaml is None:
            return []
        try:
            data = yaml.safe_load(content) or {}
        except Exception:  # noqa: BLE001
            return []
        edges: set[tuple[str, str]] = set()
        importers = data.get("importers") or {}
        root_importer = importers.get(".") or {}
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            for dep_name in (root_importer.get(section) or {}).keys():
                edges.add((project_name, dep_name))
        for key, entry in (data.get("packages") or {}).items():
            name, _version = _pnpm_key_to_name_version(str(key))
            if not name or not isinstance(entry, dict):
                continue
            for dep_name in (entry.get("dependencies") or {}).keys():
                edges.add((name, dep_name))
        return [GraphEdge(parent=parent, child=child) for parent, child in sorted(edges)]

    def _rewrite_package_json_dependency(
        self,
        content: str,
        package_name: str,
        new_version: str,
    ) -> str:
        lines = content.splitlines(keepends=True)
        section: str | None = None
        brace_depth = 0
        package_pattern = re.compile(
            r'("'
            + re.escape(package_name)
            + r'"\s*:\s*")'
            r'[^"]*'
            r'(")'
        )
        rewritten: list[str] = []
        for line in lines:
            if section is None:
                section_match = re.match(r'^\s*"(dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{', line)
                if section_match:
                    section = section_match.group(1)
                    stripped = re.sub(r'"[^"]*"', '""', line)
                    brace_depth = stripped.count("{") - stripped.count("}")
                    rewritten.append(line)
                    continue
                rewritten.append(line)
                continue

            rewritten_line = package_pattern.sub(rf"\g<1>{new_version}\g<2>", line)
            rewritten.append(rewritten_line)
            stripped = re.sub(r'"[^"]*"', '""', line)
            brace_depth += stripped.count("{") - stripped.count("}")
            if brace_depth <= 0:
                section = None
        return "".join(rewritten)

    @staticmethod
    def _install_command(manifest: ManifestInfo) -> tuple[str, list[str]]:
        if manifest.lockfile_type == "yarn_lockfile":
            return "yarn", ["install"]
        if manifest.lockfile_type == "pnpm_lockfile":
            return "pnpm", ["install"]
        return "npm", ["install"]

    @staticmethod
    def _peer_satisfies(candidate_spec: str, required_range: str) -> bool:
        candidate = candidate_spec.strip()
        required = required_range.strip()
        if not required or required in {"*", "latest"}:
            return True
        candidate_version = NpmAdapter._coerce_exact_version(candidate)
        if candidate_version is None:
            return True
        for part in required.split():
            if part.startswith(">="):
                if NpmAdapter._compare_versions(candidate_version, part[2:]) < 0:
                    return False
            elif part.startswith("<="):
                if NpmAdapter._compare_versions(candidate_version, part[2:]) > 0:
                    return False
            elif part.startswith(">"):
                if NpmAdapter._compare_versions(candidate_version, part[1:]) <= 0:
                    return False
            elif part.startswith("<"):
                if NpmAdapter._compare_versions(candidate_version, part[1:]) >= 0:
                    return False
            elif part.startswith("^"):
                lower = part[1:]
                upper = NpmAdapter._caret_upper_bound(lower)
                if (
                    NpmAdapter._compare_versions(candidate_version, lower) < 0
                    or NpmAdapter._compare_versions(candidate_version, upper) >= 0
                ):
                    return False
            elif part.startswith("~"):
                lower = part[1:]
                upper = NpmAdapter._tilde_upper_bound(lower)
                if (
                    NpmAdapter._compare_versions(candidate_version, lower) < 0
                    or NpmAdapter._compare_versions(candidate_version, upper) >= 0
                ):
                    return False
            elif re.match(r"^\d", part):
                if NpmAdapter._compare_versions(candidate_version, part) != 0:
                    return False
        return True

    @staticmethod
    def _coerce_exact_version(spec: str) -> str | None:
        stripped = spec.strip()
        if stripped.startswith(("^", "~", ">", "<", "=")):
            stripped = stripped.lstrip("^~<>= ")
        if re.match(r"^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$", stripped):
            return stripped
        return None

    @staticmethod
    def _compare_versions(left: str, right: str) -> int:
        def parts(value: str) -> list[int]:
            core = value.split("-", 1)[0].split("+", 1)[0]
            nums = [int(part) if part.isdigit() else 0 for part in core.split(".")]
            while len(nums) < 3:
                nums.append(0)
            return nums[:3]

        left_parts = parts(left)
        right_parts = parts(right)
        if left_parts < right_parts:
            return -1
        if left_parts > right_parts:
            return 1
        return 0

    @staticmethod
    def _caret_upper_bound(version: str) -> str:
        major, minor, patch = NpmAdapter._version_triplet(version)
        if major > 0:
            return f"{major + 1}.0.0"
        if minor > 0:
            return f"0.{minor + 1}.0"
        return f"0.0.{patch + 1}"

    @staticmethod
    def _tilde_upper_bound(version: str) -> str:
        major, minor, _patch = NpmAdapter._version_triplet(version)
        return f"{major}.{minor + 1}.0"

    @staticmethod
    def _version_triplet(version: str) -> tuple[int, int, int]:
        core = version.split("-", 1)[0].split("+", 1)[0]
        parts = [int(part) if part.isdigit() else 0 for part in core.split(".")]
        while len(parts) < 3:
            parts.append(0)
        return parts[0], parts[1], parts[2]
