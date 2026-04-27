#!/usr/bin/env python3
"""
Changes AI: Evaluates the impact of updating software packages.

Reads pip or uv library dependencies from a GitHub repository,
fetches current version numbers using libraries.io, and creates
a version mapping and dependency chart.
"""

import argparse
from contextlib import redirect_stdout
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

import requests
from dotenv import load_dotenv

try:
    from . import __version__
    from .cache import CacheMissError, SQLiteCache, default_cache_path
    from .currency import analyse_currency
    from .graph import build_dependency_edges, render_dot_graph
    from .impact import LLMClient, run_impact_analysis, usage_data_requires_opt_in
    from .remediation import run_remediation_plan
    from .reporting import (
        render_dot_report,
        render_html_report_bundle,
        render_json_report,
        render_markdown_report,
        render_pdf_report,
        render_sarif_report,
    )
    from .usage import analyse_usage
    from .vulnerability import (
        SEVERITY_RANK,
        scan_vulnerabilities,
        print_cve_table,
    )
except ImportError:  # pragma: no cover - direct script execution path
    from src import __version__
    from src.cache import CacheMissError, SQLiteCache, default_cache_path
    from src.currency import analyse_currency
    from src.graph import build_dependency_edges, render_dot_graph
    from src.impact import LLMClient, run_impact_analysis, usage_data_requires_opt_in
    from src.remediation import run_remediation_plan
    from src.reporting import (
        render_dot_report,
        render_html_report_bundle,
        render_json_report,
        render_markdown_report,
        render_pdf_report,
        render_sarif_report,
    )
    from src.usage import analyse_usage
    from src.vulnerability import (
        SEVERITY_RANK,
        scan_vulnerabilities,
        print_cve_table,
    )


# ---------------------------------------------------------------------------
# Repository and dependency discovery
# ---------------------------------------------------------------------------

DEPENDENCY_CANDIDATES = [
    ("requirements.txt", "pip"),
    ("requirements/base.txt", "pip"),
    ("requirements/main.txt", "pip"),
    ("requirements/prod.txt", "pip"),
    ("pyproject.toml", "pyproject"),
    ("environment.yml", "conda"),
    ("uv.lock", "uv"),
]


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL.

    Accepts URLs such as:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        github.com/owner/repo
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    pattern = r"(?:https?://)?github\.com/([^/]+)/([^/]+)$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(
            f"Invalid GitHub URL: {url!r}. "
            "Expected format: https://github.com/owner/repo"
        )
    return match.group(1), match.group(2)


def _repo_base_path(path: str | None = None) -> Path:
    value = path or _env_value("CHANGES_AI_REPO_PATH")
    return Path(value or "./repos").expanduser()


def _clone_auth_env(github_token: str | None, askpass_path: Path | None = None) -> dict:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if github_token and askpass_path is not None:
        askpass_path.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "*Username*) printf '%s\\n' x-access-token ;;\n"
            "*Password*) printf '%s\\n' \"$CHANGES_AI_GIT_TOKEN\" ;;\n"
            "*) printf '\\n' ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        askpass_path.chmod(0o700)
        env["GIT_ASKPASS"] = str(askpass_path)
        env["CHANGES_AI_GIT_TOKEN"] = github_token
    return env


def clone_github_repo(
    owner: str,
    repo: str,
    repo_base_path: str | Path | None = None,
    github_token: str | None = None,
) -> Path:
    """Clone a GitHub repository under *repo_base_path* and return its path."""
    base_path = _repo_base_path(str(repo_base_path) if repo_base_path else None)
    checkout_path = base_path / owner / repo

    if checkout_path.exists():
        if (checkout_path / ".git").is_dir():
            print(f"Using existing clone: {checkout_path}")
            return checkout_path
        if any(checkout_path.iterdir()):
            raise FileExistsError(
                f"Clone destination already exists and is not a Git repository: {checkout_path}"
            )

    checkout_path.parent.mkdir(parents=True, exist_ok=True)
    clone_url = f"https://github.com/{owner}/{repo}.git"
    print(f"Cloning repository to {checkout_path}…")

    with tempfile.TemporaryDirectory(prefix="changes-ai-git-askpass-") as tmpdir:
        askpass_path = Path(tmpdir) / "askpass.sh" if github_token else None
        env = _clone_auth_env(github_token, askpass_path)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, str(checkout_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "git clone failed").strip()
        raise RuntimeError(message)

    return checkout_path


# Dependency parsers
# ---------------------------------------------------------------------------


class DependencyParser:
    """Parses dependency files and returns {package_name: pinned_version_or_None}."""

    @staticmethod
    def parse(content: str, file_type: str) -> dict:
        dispatch = {
            "pip": DependencyParser.parse_requirements_txt,
            "pyproject": DependencyParser.parse_pyproject_toml,
            "conda": DependencyParser.parse_conda_environment_yml,
            "uv": DependencyParser.parse_uv_lock,
        }
        parser = dispatch.get(file_type)
        if parser is None:
            raise ValueError(f"Unknown dependency file type: {file_type!r}")
        return parser(content)

    @staticmethod
    def _parse_requirement_entry(requirement: str) -> tuple[str, str | None] | None:
        """Parse a single requirement-like entry into ``(name, specifier)``."""
        line = requirement.split("#")[0].strip()
        if not line:
            return None

        name_match = re.match(
            r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)", line
        )
        if not name_match:
            return None

        name = name_match.group(1)
        after_name = line[name_match.end() :]
        after_name = re.sub(r"^\[[^\]]*\]", "", after_name)
        spec_str = after_name.split(";")[0].strip()
        return name, spec_str if spec_str else None

    @staticmethod
    def parse_requirements_txt(content: str) -> dict:
        """Parse a pip requirements.txt file."""
        packages: dict = {}
        for raw_line in content.splitlines():
            line = raw_line.strip()
            # Skip blank lines, comments and pip options (e.g. -r, -c, -e)
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            parsed = DependencyParser._parse_requirement_entry(line)
            if parsed is None:
                continue
            name, spec_str = parsed
            packages[name] = spec_str
        return packages

    @staticmethod
    def parse_pyproject_toml(content: str) -> dict:
        """Parse a pyproject.toml file (PEP 621 and Poetry formats)."""
        packages: dict = {}
        if tomllib is None:
            print(
                "Warning: tomllib/tomli not available – cannot parse pyproject.toml. "
                "Install tomli for Python < 3.11.",
                file=sys.stderr,
            )
            return packages

        try:
            data = tomllib.loads(content)
        except Exception as exc:  # noqa: BLE001
            print(
                f"Warning: Failed to parse pyproject.toml as TOML: {exc}",
                file=sys.stderr,
            )
            return packages

        dep_strings: list = []

        # PEP 621 / uv style
        project = data.get("project", {})
        dep_strings.extend(project.get("dependencies", []))
        for extras_list in project.get("optional-dependencies", {}).values():
            dep_strings.extend(extras_list)

        # Poetry style
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for pkg_name, spec in poetry_deps.items():
            if pkg_name.lower() == "python":
                continue
            if isinstance(spec, str):
                normalized = spec.replace("^", ">=").replace("~", "~=")
                dep_strings.append(f"{pkg_name}{normalized}")
            elif isinstance(spec, dict):
                version = spec.get("version", "")
                normalized = version.replace("^", ">=").replace("~", "~=")
                dep_strings.append(f"{pkg_name}{normalized}")

        for dep in dep_strings:
            parsed = DependencyParser._parse_requirement_entry(dep)
            if parsed is None:
                continue
            name, spec_str = parsed
            packages[name] = spec_str

        return packages

    @staticmethod
    def parse_conda_environment_yml(content: str) -> dict:
        """Parse a Conda ``environment.yml`` dependency list."""
        packages: dict = {}
        in_dependencies = False
        in_pip_block = False
        dependencies_indent = -1
        pip_indent = -1

        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(raw_line) - len(raw_line.lstrip(" "))

            if not in_dependencies:
                if stripped == "dependencies:":
                    in_dependencies = True
                    dependencies_indent = indent
                continue

            if indent <= dependencies_indent and not stripped.startswith("- "):
                break

            if in_pip_block:
                if indent <= pip_indent:
                    in_pip_block = False
                elif stripped.startswith("- "):
                    parsed = DependencyParser._parse_requirement_entry(stripped[2:].strip())
                    if parsed is not None:
                        name, spec_str = parsed
                        packages[name] = spec_str
                    continue

            if not stripped.startswith("- "):
                continue

            entry = stripped[2:].strip()
            if entry == "pip:":
                in_pip_block = True
                pip_indent = indent
                continue

            entry = entry.split("#")[0].strip()
            if not entry:
                continue

            if "::" in entry:
                entry = entry.split("::", 1)[1].strip()

            conda_match = re.match(
                r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(.*)$",
                entry,
            )
            if not conda_match:
                continue

            name = conda_match.group(1)
            spec_str = conda_match.group(2).strip()
            if spec_str.startswith("=") and not spec_str.startswith(
                ("==", ">=", "<=", "!=", "~=")
            ):
                spec_str = f"=={spec_str[1:]}"
            packages[name] = spec_str if spec_str else None

        return packages

    @staticmethod
    def parse_uv_lock(content: str) -> dict:
        """Parse a uv.lock file (TOML format) for package names and versions."""
        packages: dict = {}

        if tomllib is not None:
            try:
                data = tomllib.loads(content)
                for pkg in data.get("package", []):
                    name = pkg.get("name")
                    version = pkg.get("version")
                    if name:
                        packages[name] = version
                return packages
            except Exception as exc:  # noqa: BLE001
                print(
                    f"Warning: TOML parsing of uv.lock failed, falling back to regex parser: {exc}",
                    file=sys.stderr,
                )

        # Regex fallback when tomllib is unavailable
        current_name: Optional[str] = None
        current_version: Optional[str] = None
        for line in content.splitlines():
            if line.startswith("[[package]]"):
                if current_name:
                    packages[current_name] = current_version
                current_name = None
                current_version = None
            else:
                nm = re.match(r'^name\s*=\s*"([^"]+)"', line)
                vm = re.match(r'^version\s*=\s*"([^"]+)"', line)
                if nm:
                    current_name = nm.group(1)
                elif vm:
                    current_version = vm.group(1)
        if current_name:
            packages[current_name] = current_version

        return packages


# ---------------------------------------------------------------------------
# Virtual environment parser
# ---------------------------------------------------------------------------


class VenvParser:
    """Reads installed packages from a local Python virtual environment."""

    @staticmethod
    def _find_site_packages(venv_path) -> Path:
        venv_path = Path(venv_path)
        candidates = sorted(
            venv_path.glob("lib/python*/site-packages"),
            key=lambda p: tuple(int(x) for x in re.findall(r"\d+", p.parent.name)),
        )
        if not candidates:
            raise FileNotFoundError(
                f"No site-packages directory found under {venv_path}. "
                "Is this a valid Python virtual environment?"
            )
        return candidates[-1]  # highest version

    @staticmethod
    def parse(venv_path) -> dict:
        venv_path = Path(venv_path)
        site = VenvParser._find_site_packages(venv_path)
        packages: dict = {}
        for dist_info in site.glob("*.dist-info"):
            metadata_file = dist_info / "METADATA"
            name: Optional[str] = None
            version: Optional[str] = None
            try:
                with metadata_file.open(encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.strip() == "":
                            break  # end of RFC-822 headers
                        if line.startswith("Name:"):
                            name = line.split(":", 1)[1].strip()
                        elif line.startswith("Version:"):
                            version = line.split(":", 1)[1].strip()
            except FileNotFoundError:
                continue
            if name and version:
                packages[name] = version
        return packages

    @staticmethod
    def get_requires(venv_path) -> dict:
        """Return {normalised_name: [normalised_dep, ...]} for all installed packages.

        Reads ``Requires-Dist`` headers from each package's METADATA file.
        Names are normalised to lowercase with hyphens so they can be compared
        directly with the output of ``VenvParser.parse``.
        """
        venv_path = Path(venv_path)
        site = VenvParser._find_site_packages(venv_path)
        requires: dict = {}
        for dist_info in site.glob("*.dist-info"):
            metadata_file = dist_info / "METADATA"
            name: Optional[str] = None
            deps: list = []
            try:
                with metadata_file.open(encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.strip() == "":
                            break
                        if line.startswith("Name:"):
                            name = line.split(":", 1)[1].strip()
                        elif line.startswith("Requires-Dist:"):
                            dep_spec = line.split(":", 1)[1].strip()
                            dep_name = re.split(r"[; (><=!]", dep_spec)[0].strip()
                            dep_name = dep_name.split("[", 1)[0].strip()
                            if dep_name:
                                deps.append(dep_name.lower().replace("_", "-"))
            except FileNotFoundError:
                continue
            if name:
                requires[name.lower().replace("_", "-")] = deps
        return requires


def find_venv(source_path) -> Path:
    """Locate a Python virtual environment inside *source_path*.

    Checks for ``.venv`` then ``venv`` (in that priority order).
    Raises ``FileNotFoundError`` if neither is found.
    """
    source_path = Path(source_path)
    for candidate in (".venv", "venv"):
        venv = source_path / candidate
        if (venv / "lib").is_dir():
            return venv
    raise FileNotFoundError(
        f"No virtual environment found under {source_path}. "
        "Expected a '.venv' or 'venv' folder containing a 'lib' directory."
    )


# libraries.io client
# ---------------------------------------------------------------------------


class LibrariesIOClient:
    """Fetches package metadata from libraries.io."""

    BASE_URL = "https://libraries.io/api"

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: SQLiteCache | None = None,
        refresh: bool = False,
        offline: bool = False,
    ) -> None:
        self.api_key = api_key
        self.cache = cache
        self.refresh = refresh
        self.offline = offline
        self.session = requests.Session()

    def _params(self) -> dict:
        return {"api_key": self.api_key} if self.api_key else {}

    _MAX_RETRIES = 3
    _DEFAULT_BACKOFF = 5.0  # seconds to wait on 429 when no Retry-After header
    _MAX_BACKOFF = 15.0

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass
        return min(self._DEFAULT_BACKOFF * (2**attempt), self._MAX_BACKOFF)

    def _get_with_retry(self, url: str) -> Optional[requests.Response]:
        """GET *url* with automatic retry on HTTP 429 (rate limit)."""
        for attempt in range(self._MAX_RETRIES):
            try:
                response = self.session.get(url, params=self._params(), timeout=30)
            except requests.RequestException as exc:
                print(f"Warning: request failed for {url}: {exc}", file=sys.stderr)
                return None
            if response.status_code != 429:
                return response
            if attempt < self._MAX_RETRIES - 1:
                wait = self._retry_delay(attempt, response.headers.get("Retry-After"))
                time.sleep(wait)
        return None  # exhausted retries

    def get_package_info(self, name: str, platform: str = "pypi") -> Optional[dict]:
        """Return the libraries.io JSON record for a package, or None on failure."""
        cache_key = f"{platform}:{name.lower()}"
        if self.cache is not None:
            cached = self.cache.get(
                "libraries_io_package",
                cache_key,
                refresh=self.refresh,
                offline=self.offline,
            )
            if cached is not None:
                return cached

        url = f"{self.BASE_URL}/{platform}/{name}"
        response = self._get_with_retry(url)
        if response is not None and response.status_code == 200:
            payload = response.json()
            if self.cache is not None:
                self.cache.set("libraries_io_package", cache_key, payload)
            return payload
        return None

    def get_latest_version(self, name: str) -> Optional[str]:
        """Return the latest stable version string for a PyPI package."""
        info = self.get_package_info(name)
        if info:
            return info.get("latest_stable_release_number") or info.get(
                "latest_release_number"
            )
        return None

    def get_dependencies(self, name: str, version: str) -> list:
        """Return the runtime dependency names of *name* at *version*."""
        cache_key = f"pypi:{name.lower()}:{version}"
        if self.cache is not None:
            cached = self.cache.get(
                "libraries_io_dependencies",
                cache_key,
                refresh=self.refresh,
                offline=self.offline,
            )
            if cached is not None:
                return list(cached)

        url = f"{self.BASE_URL}/pypi/{name}/{version}/dependencies"
        response = self._get_with_retry(url)
        if response is None or response.status_code != 200:
            return []
        data = response.json()
        dependencies = [
            d["project_name"]
            for d in data.get("dependencies", [])
            if d.get("kind") not in ("development", "test")
        ]
        if self.cache is not None:
            self.cache.set("libraries_io_dependencies", cache_key, dependencies)
        return dependencies


# Version mapping
# ---------------------------------------------------------------------------


def _concrete_version(requirement: str | None) -> str | None:
    """Return a concrete version from an exact pin or lockfile value."""
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


def _fingerprint_payload(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_version_mapping(
    packages: dict,
    libraries_client: LibrariesIOClient,
    venv_pkgs: dict | None = None,
) -> list:
    """Fetch latest versions and return a list of version-mapping dicts."""
    if not packages:
        return []

    _norm = lambda n: n.lower().replace("_", "-")
    venv_index = {_norm(k): v for k, v in (venv_pkgs or {}).items()}

    mapping = []
    total = len(packages)
    with ThreadPoolExecutor(max_workers=min(8, total)) as executor:
        latest_futures = {
            name: executor.submit(libraries_client.get_latest_version, name)
            for name in packages
        }
        for idx, (name, requirement) in enumerate(packages.items(), start=1):
            print(
                f"\r  Checking {name} ({idx}/{total})…\033[K",
                end="",
                file=sys.stderr,
            )
            latest = latest_futures[name].result()
            installed = venv_index.get(_norm(name))

            # Prefer the installed version from a local venv; otherwise use an exact pin.
            resolved = installed or _concrete_version(requirement)

            if resolved and latest:
                status = "up-to-date" if resolved == latest else "outdated"
            elif not requirement:
                status = "unpinned"
            else:
                status = "unknown"

            mapping.append(
                {
                    "name": name,
                    "installed": installed or "(unknown)",
                    "requirement": requirement or "unpinned",
                    "latest": latest or "(unknown)",
                    "status": status,
                }
            )

    print("\r\033[K", end="", file=sys.stderr)
    return mapping


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

STATUS_SYMBOL = {
    "up-to-date": "✓",
    "outdated": "⚠",
    "unpinned": "?",
    "unknown": "-",
}


def print_version_table(mapping: list) -> None:
    """Print version mapping as a human-readable table."""
    if not mapping:
        print("No packages found.")
        return

    name_w = inst_w = req_w = lat_w = 0
    for m in mapping:
        name_w = max(name_w, len(m["name"]))
        inst_w = max(inst_w, len(m["installed"]))
        req_w = max(req_w, len(m["requirement"]))
        lat_w = max(lat_w, len(m["latest"]))
    name_w = max(name_w + 2, 9)
    inst_w = max(inst_w + 2, 19)
    req_w = max(req_w + 2, 13)
    lat_w = max(lat_w + 2, 16)

    header = (
        f"{'Package':<{name_w}} {'Installed Version':<{inst_w}}"
        f" {'Requirement':<{req_w}} {'Latest Version':<{lat_w}} Status"
    )
    print(header)
    print("-" * len(header))

    for m in mapping:
        symbol = STATUS_SYMBOL.get(m["status"], "-")
        print(
            f"{m['name']:<{name_w}} {m['installed']:<{inst_w}}"
            f" {m['requirement']:<{req_w}} {m['latest']:<{lat_w}} {symbol} {m['status']}"
        )


def generate_mermaid_chart(
    packages: dict,
    libraries_client: LibrariesIOClient,
    include_transitive: bool = False,
) -> str:
    """Return a Mermaid flowchart string for the dependency graph.

    Each direct dependency is shown as a node labelled ``name\\nversion``.
    When *include_transitive* is True, runtime sub-dependencies fetched from
    libraries.io are added as edges.
    """
    lines = ["graph TD"]

    def node_id(pkg_name: str) -> str:
        # Prefix all node IDs to avoid Mermaid keyword collisions (e.g. "style").
        return "pkg_" + re.sub(r"[^A-Za-z0-9]", "_", pkg_name)

    # Nodes for direct dependencies
    for name, version in packages.items():
        label = f"{name}\\n{version}" if version else name
        lines.append(f'    {node_id(name)}["{label}"]')

    if include_transitive:
        seen_nodes: set = set(node_id(n) for n in packages)
        seen_edges: set = set()
        edge_lines: list = []
        total = len(packages)
        for idx, (name, version) in enumerate(packages.items(), start=1):
            # Resolve a concrete version for the dep lookup: strip an exact ==pin,
            # otherwise ask libraries.io for the latest (specifiers are not valid here).
            resolved = _concrete_version(
                version
            ) or libraries_client.get_latest_version(name)
            if not resolved:
                continue
            print(
                f"\r  Fetching transitive deps for {name} ({idx}/{total})…\033[K",
                end="",
                file=sys.stderr,
            )
            deps = libraries_client.get_dependencies(name, resolved)
            parent = node_id(name)
            for dep in deps:
                child = node_id(dep)
                # Declare the child node only once
                if child not in seen_nodes:
                    seen_nodes.add(child)
                    lines.append(f'    {child}["{dep}"]')
                edge = (parent, child)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    edge_lines.append(f"    {parent} --> {child}")
        lines.extend(edge_lines)
        print("\r\033[K", end="", file=sys.stderr)

    return "\n".join(lines)


def generate_ascii_chart(
    packages: dict,
    libraries_client: "LibrariesIOClient | None" = None,
    include_transitive: bool = False,
) -> str:
    """Return an ASCII dependency tree.

    When *libraries_client* is supplied and *include_transitive* is True,
    runtime sub-dependencies are fetched and shown as child nodes.
    """
    if not packages:
        return "(no packages)"

    # Build children map: direct package → [dep, …]
    children: dict[str, list[str]] = {}
    if include_transitive and libraries_client is not None:
        total = len(packages)
        for idx, (name, version) in enumerate(packages.items(), start=1):
            # Resolve a concrete version for the dep lookup: strip an exact ==pin,
            # otherwise ask libraries.io for the latest (specifiers are not valid here).
            resolved = _concrete_version(
                version
            ) or libraries_client.get_latest_version(name)
            if not resolved:
                children[name] = []
                continue
            print(
                f"\r  Fetching transitive deps for {name} ({idx}/{total})…\033[K",
                end="",
                file=sys.stderr,
            )
            children[name] = libraries_client.get_dependencies(name, resolved)
        print("\r\033[K", end="", file=sys.stderr)
    else:
        children = {name: [] for name in packages}

    lines = []
    pkg_items = list(packages.items())
    for i, (name, version) in enumerate(pkg_items):
        is_last_pkg = i == len(pkg_items) - 1
        connector = "└─" if is_last_pkg else "├─"
        ver_str = f" ({version})" if version else ""
        lines.append(f"  {connector} {name}{ver_str}")

        deps = children.get(name, [])
        prefix = "     " if is_last_pkg else "  │  "
        for j, dep in enumerate(deps):
            is_last_dep = j == len(deps) - 1
            dep_connector = "└─" if is_last_dep else "├─"
            lines.append(f"{prefix}{dep_connector} {dep}")

    return "\n".join(lines)


def _print_usage_summary(report) -> None:
    """Print a concise usage-analysis summary table."""
    print("\n=== Usage Analysis ===\n")

    if not report.records and not report.unresolved:
        print("No package references found in source.")
        return

    # Group records by package
    by_pkg: dict = {}
    for r in report.records:
        by_pkg.setdefault(r.package, []).append(r)

    pkg_w = max((len(p) for p in by_pkg), default=7)
    sym_header = "Symbols used"
    header = f"{'Package':<{pkg_w}}  {sym_header}"
    print(header)
    print("-" * len(header))
    for pkg in sorted(by_pkg):
        symbols = sorted({r.symbol for r in by_pkg[pkg]})
        print(
            f"{pkg:<{pkg_w}}  {', '.join(symbols[:5])}"
            + (" …" if len(symbols) > 5 else "")
        )

    if report.unresolved:
        print("\n--- Unresolved / flagged ---")
        for u in report.unresolved:
            loc = f"{u.source_file}:{u.line}"
            pkg_label = f"[{u.package}] " if u.package else ""
            print(f"  {u.flag:<16}  {pkg_label}{loc}")


def _print_currency_summary(records: list[dict]) -> None:
    """Print a concise currency-signal summary table."""
    print("\n=== Currency Signals ===\n")

    if not records:
        print("No currency signals available.")
        return

    pkg_w = max(max(len(r["package"]) for r in records), len("Package"))
    date_w = max(
        max(len(str(r.get("latest_release_date") or "unknown")) for r in records),
        len("Latest Release"),
    )
    header = f"{'Package':<{pkg_w}}  {'Latest Release':<{date_w}}  Signals"
    print(header)
    print("-" * len(header))
    for record in records:
        signals = ", ".join(record.get("signals") or []) or "none"
        latest_release = record.get("latest_release_date") or "unknown"
        print(f"{record['package']:<{pkg_w}}  {latest_release:<{date_w}}  {signals}")


def _wrap(text: str, width: int, indent: str) -> str:
    """Wrap *text* to *width* columns, prefixing every line after the first with *indent*."""
    import textwrap

    lines = textwrap.wrap(text, width=width - len(indent))
    return f"\n{indent}".join(lines)


def _print_impact_summary(reports: list) -> None:
    """Print a human-readable impact analysis summary."""
    print("\n=== Impact Analysis ===\n")

    if not reports:
        print("No impact reports generated.")
        return

    BREAKAGE_SYMBOL = {"NONE": "✓", "LOW": "○", "MEDIUM": "⚠", "HIGH": "✖"}
    BREAKAGE_COLOR = {
        "NONE": "\033[0;32m",  # green
        "LOW": "\033[0;34m",  # blue
        "MEDIUM": "\033[0;33m",  # yellow
        "HIGH": "\033[1;31m",  # bold red
    }
    _RESET = "\033[0m"
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    # Column widths
    pkg_w = max(len(r.package) for r in reports)
    pkg_w = max(pkg_w + 2, 9)
    upg_w = max(len(f"{r.installed_version} → {r.candidate_version}") for r in reports)
    upg_w = max(upg_w + 2, 22)
    dlt_w = 7  # "major" is longest
    brk_w = 14  # "⚠ MEDIUM (0.50)" — padded for colour alignment
    con_w = 10  # "~ MEDIUM"

    header = (
        f"{'Package':<{pkg_w}} {'Upgrade':<{upg_w}} {'Delta':<{dlt_w}}"
        f" {'Breakage':<{brk_w}} {'Confidence':<{con_w}}"
    )
    print(header)
    print("-" * len(header))

    for r in reports:
        upgrade = f"{r.installed_version} → {r.candidate_version}"
        b_sym = BREAKAGE_SYMBOL.get(r.probable_breakage, "-")
        breakage_raw = f"{b_sym} {r.probable_breakage} ({r.breakage_score:.2f})"
        if use_color:
            color = BREAKAGE_COLOR.get(r.probable_breakage, "")
            breakage_col = f"{color}{breakage_raw:<{brk_w}}{_RESET}"
        else:
            breakage_col = f"{breakage_raw:<{brk_w}}"

        conf_sym = {"LOW": "?", "MEDIUM": "~", "HIGH": "✓"}.get(r.confidence, "?")
        conf_col = f"{conf_sym} {r.confidence}"
        fallback_note = " [fallback]" if r.fallback_used else ""

        print(
            f"{r.package:<{pkg_w}} {upgrade:<{upg_w}} {r.version_delta:<{dlt_w}}"
            f" {breakage_col} {conf_col}{fallback_note}"
        )

        # Detail lines — indented under the row
        indent = "  "
        wrap_width = 90

        if r.unresolved_usage:
            print(
                f"{indent}⚠ Unresolved usage (star/dynamic import) — assumed fully used"
            )

        if r.usage_intersection:
            syms = ", ".join(r.usage_intersection[:8])
            if len(r.usage_intersection) > 8:
                syms += " …"
            print(f"{indent}Used: {syms}")

        intersecting = [c for c in r.api_changes if c.intersects_usage]
        if intersecting:
            print(f"{indent}API changes affecting your usage:")
            bullet_indent = f"{indent}    "
            for c in intersecting:
                header_line = f"{indent}  • [{c.change_type}] {c.symbol}:"
                desc_wrapped = _wrap(c.description, wrap_width, bullet_indent)
                print(f"{header_line}\n{bullet_indent}{desc_wrapped}")

        if r.evidence:
            print(f"{indent}{_wrap(r.evidence, wrap_width, indent)}")

        for citation in getattr(r, "evidence_citations", []) or []:
            print(
                f"{indent}Source: {citation.source} - {citation.label} ({citation.url})"
            )

        print()


def _print_remediation_plan(paths: list, vulns: list) -> None:
    """Print a human-readable remediation plan summary."""
    print("\n=== Remediation Plan ===\n")

    if not paths:
        print("No remediation paths generated.")
        return

    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    _RESET = "\033[0m"
    CONF_COLOR = {
        "HIGH": "\033[0;32m",  # green
        "MEDIUM": "\033[0;33m",  # yellow
        "LOW": "\033[0;34m",  # blue
    }
    PATH_LABEL = {
        "minimum_breakage": "Minimum Breakage",
        "maximum_coverage": "Maximum Coverage",
        "balanced": "Balanced",
    }

    # Collect all CVE IDs across all paths so we can summarise in the headline.
    all_cve_ids: set = set()
    for v in vulns:
        all_cve_ids.add(v.cve_id)
    total_cves = len(all_cve_ids)

    # One-line headline summarising what each path resolves.
    headline_parts = []
    for p in paths:
        label = PATH_LABEL.get(p.path_type, p.path_type)
        resolved = len(p.cves_resolved)
        headline_parts.append(f"{label.lower()} {resolved}/{total_cves}")
    if headline_parts:
        print(f"{len(paths)} path(s) generated: {' · '.join(headline_parts)}.\n")

    wrap_width = 90
    indent = "  "

    for p in paths:
        label = PATH_LABEL.get(p.path_type, p.path_type)
        conf_sym = {"LOW": "?", "MEDIUM": "~", "HIGH": "✓"}.get(p.confidence, "?")

        if use_color:
            color = CONF_COLOR.get(p.confidence, "")
            conf_str = f"{color}{conf_sym} {p.confidence}{_RESET}"
        else:
            conf_str = f"{conf_sym} {p.confidence}"

        fallback_note = " [fallback]" if p.fallback_used else ""
        print(f"[{label}]{fallback_note}")

        # Rationale (immediately under the title)
        if p.rationale:
            print(f"{indent}{_wrap(p.rationale, wrap_width, indent)}")
            print()

        print(
            f"{indent}Exposure: {p.exposure_score:.2f}  "
            f"Breakage: {p.breakage_score:.2f}  "
            f"Confidence: {conf_str}"
        )

        # Upgrades
        if p.upgrades:
            for u in p.upgrades:
                cve_note = (
                    f"  (fixes {', '.join(u.fixes_cves)})" if u.fixes_cves else ""
                )
                print(
                    f"{indent}↑  {u.package}  {u.from_version} → {u.to_version}{cve_note}"
                )
        else:
            print(f"{indent}(no upgrades)")

        # CVE resolution summary
        if p.cves_resolved:
            print(f"{indent}Resolves:   {', '.join(sorted(p.cves_resolved))}")
        if p.cves_unresolved:
            print(f"{indent}Open:       {', '.join(sorted(p.cves_unresolved))}")
        if p.cves_no_fix:
            print(f"{indent}No fix:     {', '.join(sorted(p.cves_no_fix))}")

        print()

    # No-fix callout (shown once, below all paths).
    no_fix_cves: set = set()
    for p in paths:
        no_fix_cves.update(p.cves_no_fix)
    if no_fix_cves:
        # Build a severity lookup for display.
        sev_lookup: dict = {}
        for v in vulns:
            sev_lookup[v.cve_id] = v.severity
        print("=== No Fix Available ===\n")
        for cve_id in sorted(no_fix_cves):
            sev = sev_lookup.get(cve_id, "UNKNOWN")
            # Find the package name.
            pkg = next((v.package for v in vulns if v.cve_id == cve_id), "unknown")
            print(
                f"  ⚠ {cve_id} ({sev}) in {pkg} — no fix version known. "
                "Consider replacing, pinning below the affected range, or accepting the risk."
            )
        print()


def _print_cache_entries(cache: SQLiteCache) -> None:
    entries = cache.list_entries()
    if not entries:
        print("Cache is empty.")
        return

    source_w = max(max(len(e.source) for e in entries), len("Source"))
    key_w = max(max(len(e.cache_key) for e in entries), len("Key"))
    header = f"{'Source':<{source_w}}  {'Key':<{key_w}}  Expires"
    print(header)
    print("-" * len(header))
    for entry in entries:
        print(
            f"{entry.source:<{source_w}}  {entry.cache_key:<{key_w}}  {entry.expires_at}"
        )


def _env_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _resolve_output_path(
    path: str, env_dir_var: str = "CHANGES_AI_REPORT_PATH"
) -> Path:
    output_path = Path(path).expanduser()
    output_dir = _env_value(env_dir_var)
    if output_dir and not output_path.is_absolute():
        output_path = Path(output_dir).expanduser() / output_path
    return output_path


REPORT_FORMAT_EXTENSIONS = {
    "json": "json",
    "table": "txt",
    "md": "md",
    "html": "html",
    "pdf": "pdf",
    "sarif": "sarif",
    "dot": "dot",
}
REPORT_FORMAT_CHOICES = tuple(REPORT_FORMAT_EXTENSIONS)


def _report_output_folder() -> Path | None:
    value = _env_value("CHANGES_AI_REPORT_PATH")
    return Path(value).expanduser() if value else None


def _timestamped_report_path(report_format: str, output_dir: str | Path) -> Path:
    extension = REPORT_FORMAT_EXTENSIONS.get(report_format, report_format)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if report_format == "html":
        output_path = Path(output_dir).expanduser() / f"report_{timestamp}"
    else:
        output_path = Path(output_dir).expanduser() / f"report_{timestamp}.{extension}"
    suffix = 1
    while output_path.exists():
        if report_format == "html":
            output_path = Path(output_dir).expanduser() / f"report_{timestamp}_{suffix}"
        else:
            output_path = (
                Path(output_dir).expanduser()
                / f"report_{timestamp}_{suffix}.{extension}"
            )
        suffix += 1
    return output_path


def _default_report_format(default: str = "json") -> str:
    value = _env_value("CHANGES_AI_REPORT_FORMAT")
    if not value:
        return default
    normalized = value.lower()
    return normalized if normalized in REPORT_FORMAT_EXTENSIONS else default


def _default_report_template() -> str | None:
    return _env_value("CHANGES_AI_REPORT_TEMPLATE")


def _summary_target_word_count(report: dict) -> int:
    packages = len(report.get("packages") or [])
    vulns = len(report.get("vulnerabilities") or [])
    impacts = len(report.get("impact_reports") or [])
    paths = len(report.get("remediation_paths") or [])
    unresolved = len((report.get("usage") or {}).get("unresolved") or [])
    complexity = packages + (vulns * 3) + (impacts * 4) + (paths * 6) + unresolved
    return max(100, min(300, 100 + complexity * 4))


def _build_executive_summary_prompt_data(report: dict) -> dict:
    vulns = report.get("vulnerabilities") or []
    impacts = report.get("impact_reports") or []
    paths = report.get("remediation_paths") or []
    currency = report.get("currency") or []
    usage = report.get("usage") or {}
    severity_counts: dict[str, int] = {}
    for vuln in vulns:
        severity = str(vuln.get("severity") or "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    top_vulnerabilities = sorted(
        vulns,
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity") or "UNKNOWN"), 0),
            str(item.get("package") or ""),
            str(item.get("cve_id") or ""),
        ),
    )[:8]
    top_impacts = sorted(
        impacts,
        key=lambda item: (
            -float(item.get("breakage_score") or 0.0),
            str(item.get("package") or ""),
        ),
    )[:6]
    remediation_paths = sorted(
        paths,
        key=lambda item: (
            float(item.get("exposure_score") or 1.0),
            float(item.get("breakage_score") or 1.0),
        ),
    )[:3]
    noteworthy_currency = [
        {
            "package": item.get("package"),
            "installed_version": item.get("installed_version"),
            "latest_version": item.get("latest_version"),
            "signals": item.get("signals") or [],
        }
        for item in currency
        if item.get("signals")
    ][:6]
    unresolved_usage = [
        {
            "package": item.get("package"),
            "source_file": item.get("source_file"),
            "flag": item.get("flag"),
        }
        for item in (usage.get("unresolved") or [])
    ][:6]
    return {
        "run": report.get("run") or {},
        "package_count": len(report.get("packages") or []),
        "severity_counts": severity_counts,
        "top_vulnerabilities": [
            {
                "package": item.get("package"),
                "cve_id": item.get("cve_id"),
                "severity": item.get("severity"),
                "installed_version": item.get("installed_version"),
                "fixed_versions": item.get("fixed_versions") or [],
            }
            for item in top_vulnerabilities
        ],
        "top_impacts": [
            {
                "package": item.get("package"),
                "candidate_version": item.get("candidate_version"),
                "probable_breakage": item.get("probable_breakage"),
                "breakage_score": item.get("breakage_score"),
                "confidence": item.get("confidence"),
            }
            for item in top_impacts
        ],
        "remediation_paths": [
            {
                "path_type": item.get("path_type"),
                "upgrade_count": len(item.get("upgrades") or []),
                "resolved_cves": len(item.get("cves_resolved") or []),
                "open_cves": len(item.get("cves_unresolved") or []),
                "no_fix_cves": len(item.get("cves_no_fix") or []),
                "exposure_score": item.get("exposure_score"),
                "breakage_score": item.get("breakage_score"),
                "confidence": item.get("confidence"),
                "rationale": item.get("rationale"),
            }
            for item in remediation_paths
        ],
        "currency_signals": noteworthy_currency,
        "usage": {
            "record_count": len(usage.get("records") or []),
            "unresolved_count": len(usage.get("unresolved") or []),
            "unresolved_samples": unresolved_usage,
        },
    }


def _fallback_executive_summary_narrative(report: dict) -> str:
    run = report.get("run") or {}
    packages = report.get("packages") or []
    vulns = report.get("vulnerabilities") or []
    impacts = report.get("impact_reports") or []
    paths = report.get("remediation_paths") or []
    currency = report.get("currency") or []
    usage = report.get("usage") or {}
    unresolved = usage.get("unresolved") or []
    severity_counts: dict[str, int] = {}
    for vuln in vulns:
        severity = str(vuln.get("severity") or "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    severity_summary = (
        ", ".join(
            f"{count} {severity.lower()}"
            for severity, count in sorted(
                severity_counts.items(),
                key=lambda item: SEVERITY_RANK.get(item[0], 0),
                reverse=True,
            )
        )
        or "no known vulnerabilities"
    )
    return (
        f"Changes AI completed a dependency review for {run.get('locator') or 'the target project'} across {len(packages)} tracked packages. "
        f"The scan identified {len(vulns)} known vulnerabilities, made up of {severity_summary}, and collected currency signals for {len(currency)} packages to show how far behind each dependency is from the current release line. "
        f"Usage analysis {'found unresolved or dynamic references that lower certainty in the impact estimate' if unresolved else 'did not report unresolved source-usage flags, which improves confidence in the downstream impact estimate'}. "
        f"The impact stage produced {len(impacts)} upgrade assessments, and the remediation planner returned {len(paths)} ranked upgrade paths that balance exposure reduction against likely breakage. "
        "Overall, this run gives a concise picture of the present security exposure, the likely cost of fixing it, and the most credible path for reducing risk with the evidence available from the project and package metadata."
    )


def _generate_executive_summary_narrative(
    report: dict,
    *,
    api_key: str | None,
    model: str,
    api_base: str,
    cache: SQLiteCache,
    refresh: bool,
    offline: bool,
) -> str:
    fallback = _fallback_executive_summary_narrative(report)
    if not api_key:
        return fallback

    client = LLMClient(
        api_key=api_key,
        model=model,
        api_base=api_base,
        cache=cache,
        refresh=refresh,
        offline=offline,
    )
    target_words = _summary_target_word_count(report)
    prompt_data = _build_executive_summary_prompt_data(report)
    try:
        content = client.chat(
            [
                {
                    "role": "system",
                    "content": (
                        "You write concise executive summaries for software dependency risk reports. "
                        "Return plain prose only, with no bullets, no headings, and no markdown fences."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Write an executive summary narrative of about {target_words} words. "
                        "It must stay between 100 and 300 words, with length proportional to the complexity of the findings. "
                        "Summarize the overall exposure, the likely upgrade risk, and the most important remediation outcome if one exists. "
                        "Do not restate raw tables. Use clear prose only.\n\n"
                        f"<data>{json.dumps(prompt_data, indent=2, sort_keys=True)}</data>"
                    ),
                },
            ]
        )
    except CacheMissError:
        return fallback

    if not content:
        return fallback
    words = content.strip().split()
    if len(words) < 100:
        return fallback
    if len(words) > 300:
        return " ".join(words[:300]).rstrip(" ,;:") + "."
    return content.strip()


def _executive_summary_api_key(impact_analysis_enabled: bool) -> str | None:
    if not impact_analysis_enabled:
        return None
    return os.environ.get("OPENAI_API_KEY")


def _build_cve_scan_packages(
    packages: dict,
    venv_pkgs: dict | None,
) -> tuple[dict, list[tuple[str, str | None]]]:
    skipped: list[tuple[str, str | None]] = []

    if venv_pkgs:
        _norm = lambda n: n.lower().replace("_", "-")
        venv_index = {_norm(k): v for k, v in venv_pkgs.items()}
        scan_packages = {}
        for name, requirement in packages.items():
            installed_version = venv_index.get(_norm(name))
            concrete_version = installed_version or _concrete_version(requirement)
            if concrete_version:
                scan_packages[name] = concrete_version
            else:
                skipped.append((name, requirement))

        scan_norm = {_norm(k) for k in scan_packages}
        for name, version in venv_pkgs.items():
            norm_name = _norm(name)
            if norm_name not in scan_norm:
                scan_packages[name] = version
                scan_norm.add(norm_name)
        return scan_packages, skipped

    scan_packages = {}
    for name, requirement in packages.items():
        concrete_version = _concrete_version(requirement)
        if concrete_version:
            scan_packages[name] = concrete_version
        else:
            skipped.append((name, requirement))
    return scan_packages, skipped


def _build_graph_packages(
    packages: dict,
    venv_pkgs: dict | None,
    *,
    include_installed: bool,
) -> dict:
    """Return the package set used to construct cached dependency edges.

    By default this is the declared manifest package set. When
    ``include_installed`` is true, any additional packages discovered in
    the local virtualenv are included as direct project dependencies too.

    This keeps the report graph aligned with the package universe used by
    CVE scanning, which can include installed-but-undeclared packages.
    Declared manifest entries win over venv-discovered versions so we do
    not discard the user's original requirement metadata.
    """
    graph_packages = dict(packages)
    if include_installed and venv_pkgs:
        for name, version in venv_pkgs.items():
            graph_packages.setdefault(name, version)
    return graph_packages


def _format_skipped_cve_packages(skipped: list[tuple[str, str | None]]) -> str:
    if not skipped:
        return ""
    preview = ", ".join(
        f"{name} ({requirement or 'unpinned'})" for name, requirement in skipped[:8]
    )
    if len(skipped) > 8:
        preview += f", ... {len(skipped) - 8} more"
    return (
        "Warning: CVE scan skipped "
        f"{len(skipped)} package(s) without a concrete installed version. "
        "Use exact pins, a lockfile, or scan a project with a local virtual "
        f"environment to avoid false negatives: {preview}"
    )


def _is_output_directory(output_path: Path, requested_path: str) -> bool:
    """Return True if the output path should be treated as a directory.

    A path is treated as a directory only when it already exists as one,
    or when the user explicitly appended a path separator (e.g. ``reports/``).
    Every other path — including extensionless names like ``report`` — is
    treated as a plain file path so users are not surprised by automatic
    timestamped filenames.
    """
    return output_path.is_dir() or requested_path.endswith(("/", "\\"))


def _resolve_report_output_path(
    report_format: str,
    requested_path: str | None = None,
) -> Path | None:
    if requested_path:
        output_path = Path(requested_path).expanduser()
        if _is_output_directory(output_path, requested_path):
            return _timestamped_report_path(report_format, output_path)
        return output_path

    output_folder = _report_output_folder()
    if output_folder is None:
        if report_format == "html":
            return _timestamped_report_path(report_format, Path.cwd())
        return None
    return _timestamped_report_path(report_format, output_folder)


def _render_version_table(mapping: list) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print_version_table(mapping)
    return buffer.getvalue().rstrip("\n")


def _render_cached_report(
    report: dict,
    report_format: str,
    run_id: int,
    report_template: str | None = None,
) -> str | bytes | dict[str, str]:
    if report_format == "json":
        return render_json_report(report)
    if report_format == "md":
        return render_markdown_report(report).rstrip("\n")
    if report_format == "html":
        return render_html_report_bundle(report, css_path=report_template)
    if report_format == "pdf":
        return render_pdf_report(report, css_path=report_template)
    if report_format == "sarif":
        return render_sarif_report(report)
    if report_format == "dot":
        return render_dot_report(report)
    if report_format == "table":
        return f"Run: {run_id}\n\n{_render_version_table(report['packages'])}"
    raise ValueError(f"Unsupported report format: {report_format}")


def _write_text_output(path: str | Path, content: str) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _write_report_output(path: str | Path, content: str | bytes) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        output_path.write_bytes(content)
    else:
        output_path.write_text(content, encoding="utf-8")
    return output_path


def _write_html_report_output(path: str | Path, bundle: dict[str, str]) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.mkdir(parents=True, exist_ok=True)
    for name, content in bundle.items():
        (output_path / name).write_text(content, encoding="utf-8")
    return output_path


def _run_cache_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="changes-ai cache",
        description="Inspect or clear the Changes AI SQLite cache.",
    )
    parser.add_argument(
        "--cache-db",
        default=str(default_cache_path()),
        help=(
            "Path to the SQLite cache database. Defaults to CHANGES_AI_CACHE_DB "
            "when set."
        ),
    )
    subparsers = parser.add_subparsers(dest="cache_action", required=True)
    list_parser = subparsers.add_parser("list", help="List cached API entries.")
    list_parser.add_argument(
        "--cache-db",
        default=argparse.SUPPRESS,
        help="Path to the SQLite cache database.",
    )
    clear_parser = subparsers.add_parser("clear", help="Clear cached API entries.")
    clear_parser.add_argument(
        "--cache-db",
        default=argparse.SUPPRESS,
        help="Path to the SQLite cache database.",
    )
    clear_parser.add_argument(
        "--source",
        help="Only clear one cache source, e.g. libraries_io_package.",
    )
    args = parser.parse_args(argv)

    cache = SQLiteCache(args.cache_db)
    try:
        if args.cache_action == "list":
            _print_cache_entries(cache)
        elif args.cache_action == "clear":
            removed = cache.clear(source=args.source)
            print(f"Removed {removed} cache entr{'y' if removed == 1 else 'ies'}.")
    finally:
        cache.close()


def _run_report_command(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog="changes-ai report",
        description="Render cached run data without re-running the scan.",
    )
    parser.add_argument(
        "run_id", nargs="?", type=int, help="Run ID to report; defaults to latest run."
    )
    parser.add_argument(
        "--format",
        choices=REPORT_FORMAT_CHOICES,
        default=_default_report_format("json"),
        help=(
            "Report output format. Defaults to CHANGES_AI_REPORT_FORMAT when set, "
            "otherwise json."
        ),
    )
    parser.add_argument(
        "--report-template",
        default=_default_report_template(),
        help=(
            "PDF report template name or path to a CSS file. Defaults to "
            "CHANGES_AI_REPORT_TEMPLATE when set, otherwise the built-in template."
        ),
    )
    parser.add_argument(
        "--cache-db",
        default=str(default_cache_path()),
        help=(
            "Path to the SQLite cache database. Defaults to CHANGES_AI_CACHE_DB "
            "when set."
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
        help=(
            "Write the rendered report to a file or directory. Existing directory "
            "outputs use report_YYYYMMDD_HHMMSS with the selected format extension; "
            "html reports create a folder containing index.html and style.css. "
            "When omitted, CHANGES_AI_REPORT_PATH is used as the report "
            "directory if set; otherwise the report is written to stdout."
        ),
    )
    args = parser.parse_args(argv)
    cache = SQLiteCache(args.cache_db)
    try:
        run_id = args.run_id if args.run_id is not None else cache.latest_run_id()
        if run_id is None:
            print("No cached runs found.")
            return
        report = cache.get_run_report(run_id)
        if report is None:
            print(f"No cached run found for run ID {run_id}.", file=sys.stderr)
            sys.exit(1)
        output_path = _resolve_report_output_path(args.format, args.output)

        rendered = _render_cached_report(
            report,
            args.format,
            run_id,
            report_template=args.report_template,
        )
        if args.format == "table" and output_path is None:
            print(f"Run: {run_id}\n")
            print_version_table(report["packages"])
            return

        if args.format == "html":
            if output_path is None:
                output_path = _timestamped_report_path("html", Path.cwd())
            if not isinstance(rendered, dict):
                raise RuntimeError(
                    "HTML report rendering did not return an asset bundle"
                )
            output_path = _write_html_report_output(output_path, rendered)
            print(f"Report written to {output_path}")
        elif output_path is not None:
            content = rendered if isinstance(rendered, bytes) else rendered + "\n"
            output_path = _write_report_output(output_path, content)
            print(f"Report written to {output_path}")
        elif isinstance(rendered, bytes):
            sys.stdout.buffer.write(rendered)
        else:
            print(rendered)
    finally:
        cache.close()


def main() -> None:
    # Load .env file (if present) before parsing arguments so that
    # LIBRARIES_IO_API_KEY and other variables are available via os.environ.
    load_dotenv()

    raw_argv = sys.argv[1:]
    if raw_argv and raw_argv[0] == "cache":
        _run_cache_command(raw_argv[1:])
        return
    if raw_argv and raw_argv[0] == "report":
        _run_report_command(raw_argv[1:])
        return
    if raw_argv and raw_argv[0] == "scan":
        sys.argv = [sys.argv[0]] + raw_argv[1:]
    elif raw_argv and raw_argv[0] == "graph":
        sys.argv = [sys.argv[0]] + raw_argv[1:] + ["--chart"]
    elif raw_argv and raw_argv[0] == "cves":
        sys.argv = [sys.argv[0]] + raw_argv[1:] + ["--cve-scan"]
    elif raw_argv and raw_argv[0] == "usage":
        sys.argv = [sys.argv[0]] + raw_argv[1:] + ["--usage-analysis"]
    elif raw_argv and raw_argv[0] == "plan":
        sys.argv = (
            [sys.argv[0]] + raw_argv[1:] + ["--cve-scan", "--impact-analysis", "--plan"]
        )

    parser = argparse.ArgumentParser(
        prog="changes-ai",
        description=(
            "Evaluate the impact of updating software packages in a GitHub repository."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
    changes-ai --url https://github.com/owner/repo
    changes-ai --url https://github.com/owner/repo --libraries-io-key YOUR_KEY
    changes-ai --url https://github.com/owner/repo --chart
    changes-ai --source /path/to/project
    changes-ai --source /path/to/project --output table
    changes-ai scan --source /path/to/project --offline
    changes-ai cache list
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--url",
        metavar="URL",
        help="GitHub repository URL (e.g. https://github.com/owner/repo)",
    )
    input_group.add_argument(
        "--source",
        metavar="PATH",
        help=(
            "Path to a local project directory. Supported dependency manifests "
            "are used when present; otherwise '.venv' or 'venv' is auto-discovered. "
            "Defaults to CHANGES_AI_SOURCE_PATH from .env when set."
        ),
    )
    parser.add_argument(
        "--libraries-io-key",
        metavar="KEY",
        help=(
            "libraries.io API key (recommended to avoid rate limits). "
            "Falls back to the LIBRARIES_IO_API_KEY environment variable / .env file."
        ),
    )
    parser.add_argument(
        "--github-token",
        metavar="TOKEN",
        help="GitHub personal access token (for private repos / higher rate limits)",
    )
    parser.add_argument(
        "--repo-path",
        metavar="PATH",
        default=_env_value("CHANGES_AI_REPO_PATH"),
        help=(
            "Directory where --url repositories are cloned. Defaults to "
            "CHANGES_AI_REPO_PATH or ./repos."
        ),
    )
    parser.add_argument(
        "--cache-db",
        default=str(default_cache_path()),
        help=(
            "Path to the SQLite cache database. Defaults to CHANGES_AI_CACHE_DB "
            "from the environment / .env when set."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use only cached external API data and fail clearly when required data is missing.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Bypass cached external API data and refresh entries from upstream services.",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json", "both"],
        default="table",
        help="Version-mapping output format (default: table)",
    )
    parser.add_argument(
        "--format",
        choices=REPORT_FORMAT_CHOICES,
        default=_default_report_format("md"),
        help=(
            "Summary report output format when scan-generated reports are written. "
            "Defaults to CHANGES_AI_REPORT_FORMAT when set, otherwise md."
        ),
    )
    parser.add_argument(
        "--chart",
        action="store_true",
        help="Generate a dependency chart",
    )
    parser.add_argument(
        "--chart-format",
        choices=["mermaid", "ascii", "dot", "both"],
        default="ascii",
        help="Chart format when --chart is used (default: ascii)",
    )
    parser.add_argument(
        "--chart-output",
        metavar="FILE",
        default=_env_value("CHANGES_AI_CHART_OUTPUT"),
        help=(
            "Write the selected chart format to FILE instead of stdout. "
            "Relative paths are resolved under CHANGES_AI_REPORT_PATH when set."
        ),
    )
    parser.add_argument(
        "--transitive",
        action="store_true",
        help=(
            "Include transitive dependencies in the Mermaid chart "
            "(requires additional libraries.io API calls)"
        ),
    )
    parser.add_argument(
        "--report-output",
        metavar="DIR_OR_FILE",
        help=(
            "Write a summary report to a file or directory. Directory outputs "
            "use report_YYYYMMDD_HHMMSS.<format>; html reports create a folder "
            "containing index.html and style.css. Format defaults to "
            "CHANGES_AI_REPORT_FORMAT or md. When omitted, "
            "CHANGES_AI_REPORT_PATH is used as the report directory."
        ),
    )
    parser.add_argument(
        "--report-template",
        default=_default_report_template(),
        help=(
            "PDF report template name or path to a CSS file for scan-generated "
            "reports. Defaults to CHANGES_AI_REPORT_TEMPLATE when set, "
            "otherwise the built-in template."
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Run the full analysis suite: dependency chart, CVE scan, usage "
            "analysis, LLM impact analysis, and remediation planning."
        ),
    )
    parser.add_argument(
        "--cve-scan",
        action="store_true",
        help="Scan packages for known vulnerabilities via the OSV database",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        default="LOW",
        metavar="LEVEL",
        help=(
            "Only display CVEs at or above this severity level "
            "(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN, default: LOW)"
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        default=None,
        metavar="LEVEL",
        help=(
            "Exit with code 2 if any CVE at or above LEVEL is found "
            "(only meaningful with --cve-scan)"
        ),
    )
    parser.add_argument(
        "--usage-analysis",
        action="store_true",
        help="Analyse which symbols from each package the project's source actually uses (requires --source)",
    )
    parser.add_argument(
        "--impact-analysis",
        action="store_true",
        help=(
            "Run LLM-backed impact analysis for each vulnerable package (requires --cve-scan). "
            "Uses OPENAI_API_KEY and OPENAI_MODEL from environment / .env."
        ),
    )
    parser.add_argument(
        "--allow-commercial-usage-data",
        action="store_true",
        help=(
            "Allow source-derived usage-analysis data to be sent to known hosted "
            "commercial LLM endpoints. Can also be enabled with "
            "CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA=1."
        ),
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help=(
            "Run LLM-backed remediation planner and produce ranked upgrade paths "
            "(requires --impact-analysis). Uses OPENAI_API_KEY and OPENAI_MODEL."
        ),
    )

    args = parser.parse_args()

    if not args.url and not args.source:
        args.source = _env_value("CHANGES_AI_SOURCE_PATH")

    if args.all:
        args.chart = True
        args.cve_scan = True
        args.usage_analysis = True
        args.impact_analysis = True
        args.plan = True

    if args.offline and args.refresh:
        print(
            "Error: --offline and --refresh cannot be used together.", file=sys.stderr
        )
        sys.exit(1)

    # No arguments → print help and exit cleanly
    if not args.url and not args.source:
        parser.print_help()
        sys.exit(0)

    # Resolve keys: CLI flag > environment variable (.env or shell).
    libraries_io_key = args.libraries_io_key or os.environ.get("LIBRARIES_IO_API_KEY")
    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")

    cloned_repo_locator = None
    if args.url:
        try:
            owner, repo = parse_github_url(args.url)
            clone_path = clone_github_repo(
                owner,
                repo,
                repo_base_path=args.repo_path,
                github_token=github_token,
            )
        except (ValueError, FileExistsError, RuntimeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        args.source = str(clone_path)
        cloned_repo_locator = f"github:{owner}/{repo}"

    # --- Fetch packages (venv or GitHub) ---------------------------------
    scan_locator = ""
    dependency_file_path = "dependency-manifest"
    unused_packages: dict | None = None  # set only when a venv can be diffed
    venv_pkgs: dict | None = None  # installed versions from venv (for CVE scan)
    packages = None
    if args.source:
        source_path = Path(args.source)
        scan_locator = cloned_repo_locator or str(source_path.resolve())
        # Try dependency files in the shared priority order.
        for rel_path, file_type in DEPENDENCY_CANDIDATES:
            dep_file = source_path / rel_path
            if dep_file.is_file():
                print(f"Analysing source: {args.source} (dependency file: {rel_path})")
                dependency_file_path = rel_path
                try:
                    content = dep_file.read_text(encoding="utf-8")
                except OSError as exc:
                    print(f"Error reading {dep_file}: {exc}", file=sys.stderr)
                    sys.exit(1)
                packages = DependencyParser.parse(content, file_type)
                if not packages:
                    packages = None
                    continue
                # Detect packages installed in the venv but not declared as deps.
                try:
                    venv_path = find_venv(args.source)
                    venv_pkgs = VenvParser.parse(venv_path)
                    declared = {n.lower().replace("_", "-") for n in packages}
                    # Build transitive closure using venv METADATA dep graph so
                    # that indirect deps (e.g. certifi under requests) are not
                    # labelled as unused.
                    dep_graph = VenvParser.get_requires(venv_path)
                    transitive: set = set()
                    queue = list(declared)
                    while queue:
                        pkg = queue.pop()
                        for dep in dep_graph.get(pkg, []):
                            if dep not in transitive and dep not in declared:
                                transitive.add(dep)
                                queue.append(dep)
                    unused_packages = {
                        name: ver
                        for name, ver in venv_pkgs.items()
                        if name.lower().replace("_", "-") not in declared
                        and name.lower().replace("_", "-") not in transitive
                    }
                except FileNotFoundError:
                    pass  # No venv present — skip unused detection
                break

        if packages is None:
            # No dependency file found — fall back to reading the venv directly.
            try:
                venv_path = find_venv(args.source)
            except FileNotFoundError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)
            print(f"Analysing source: {args.source} (venv: {venv_path})")
            dependency_file_path = str(venv_path)
            try:
                packages = VenvParser.parse(venv_path)
                venv_pkgs = packages
            except FileNotFoundError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                sys.exit(1)

    if not packages:
        print("No packages found.")
        sys.exit(0)

    print(f"Packages detected: {len(packages)}")

    # --- Fetch version info from libraries.io ----------------------------
    cache = SQLiteCache(args.cache_db)
    libraries_client = LibrariesIOClient(
        api_key=libraries_io_key,
        cache=cache,
        refresh=args.refresh,
        offline=args.offline,
    )
    if not libraries_io_key:
        print(
            "Note: No libraries.io API key found (--libraries-io-key or "
            "LIBRARIES_IO_API_KEY in .env). "
            "Unauthenticated requests are rate-limited (~60/min)."
        )

    run_id = cache.start_run(
        locator=scan_locator,
        source_fingerprint={
            "packages": packages,
            "dependency_file": dependency_file_path,
        },
        run_fingerprint=_fingerprint_payload(
            {
                "packages": packages,
                "source": scan_locator,
                "dependency_file": dependency_file_path,
                "flags": {
                    "cve_scan": args.cve_scan,
                    "usage_analysis": args.usage_analysis,
                    "impact_analysis": args.impact_analysis,
                    "plan": args.plan,
                },
            }
        ),
    )

    print("Fetching version information from libraries.io…")
    try:
        mapping = build_version_mapping(packages, libraries_client, venv_pkgs)
    except CacheMissError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
        cache.close()
        sys.exit(1)
    cache.store_packages(run_id, mapping)
    currency_records = analyse_currency(mapping, libraries_client)
    cache.store_currency_records(run_id, currency_records)

    project_graph_name = (
        Path(scan_locator).name if args.source else scan_locator.replace("github:", "")
    )
    graph_packages = _build_graph_packages(
        packages,
        venv_pkgs,
        include_installed=args.cve_scan,
    )
    graph_edges = build_dependency_edges(
        graph_packages,
        project_node=project_graph_name or "project",
        installed_versions=venv_pkgs,
        libraries_client=libraries_client,
        include_transitive=args.transitive,
    )
    cache.store_dependency_edges(run_id, graph_edges)

    # --- Version mapping output ------------------------------------------
    if args.output in ("table", "both"):
        print("\n=== Version Mapping ===\n")
        print_version_table(mapping)

    if args.output in ("json", "both"):
        print("\n=== JSON Output ===\n")
        print(json.dumps(mapping, indent=2))

    # --- Dependency chart ------------------------------------------------
    if args.chart:
        if args.chart_format in ("ascii", "both"):
            try:
                ascii_chart = generate_ascii_chart(
                    packages,
                    libraries_client=libraries_client,
                    include_transitive=args.transitive,
                )
            except CacheMissError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
                cache.close()
                sys.exit(1)
            if args.chart_output and args.chart_format == "ascii":
                output_path = _write_text_output(
                    _resolve_output_path(args.chart_output), ascii_chart + "\n"
                )
                print(f"ASCII chart written to {output_path}")
            else:
                print("\n=== Dependency Chart (ASCII) ===\n")
                print(ascii_chart)

        if args.chart_format == "dot":
            dot_graph = render_dot_graph(
                graph_edges,
                graph_name=project_graph_name or "project",
            )
            if args.chart_output:
                output_path = _write_text_output(
                    _resolve_output_path(args.chart_output), dot_graph + "\n"
                )
                print(f"DOT graph written to {output_path}")
            else:
                print("\n=== Dependency Chart (DOT) ===\n")
                print(dot_graph)

        if args.chart_format in ("mermaid", "both"):
            print("\nGenerating Mermaid chart…")
            try:
                mermaid = generate_mermaid_chart(
                    packages,
                    libraries_client,
                    include_transitive=args.transitive,
                )
            except CacheMissError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
                cache.close()
                sys.exit(1)
            if args.chart_output:
                mermaid = "```mermaid\n" + mermaid + "\n```\n"
                output_path = _write_text_output(
                    _resolve_output_path(args.chart_output), mermaid + "\n"
                )
                print(f"Mermaid chart written to {output_path}")
            else:
                print("\n=== Dependency Chart (Mermaid) ===\n")
                print(mermaid)

    # --- Unused packages -------------------------------------------------
    if unused_packages is not None:
        print("\n=== Unused Packages ===\n")
        if unused_packages:
            for pkg_name, pkg_ver in sorted(
                unused_packages.items(), key=lambda x: x[0].lower()
            ):
                print(f"  - {pkg_name} {pkg_ver}")
        else:
            print("  None")

    # --- Summary ---------------------------------------------------------
    counts = {}
    for m in mapping:
        counts[m["status"]] = counts.get(m["status"], 0) + 1

    print("\n=== Summary ===")
    label_w = 15  # width for the left-hand label column
    print(f"{'Total packages':<{label_w}}: {len(mapping)}")
    print(f"{'Up-to-date':<{label_w}}: {counts.get('up-to-date', 0)}")
    print(f"{'Outdated':<{label_w}}: {counts.get('outdated', 0)}")
    print(f"{'Unpinned':<{label_w}}: {counts.get('unpinned', 0)}")
    print(f"{'Unknown':<{label_w}}: {counts.get('unknown', 0)}")
    if unused_packages is not None:
        print(f"{'Unused':<{label_w}}: {len(unused_packages)}")
    else:
        print(f"{'Unused':<{label_w}}: N/A")

    _print_currency_summary(currency_records)

    # --- CVE scan --------------------------------------------------------
    all_vulns: list = []
    if args.cve_scan:
        print("\nScanning for vulnerabilities via OSV…")
        # Build the scan set from declared packages + anything else installed in
        # the venv (unused packages), using concrete installed versions throughout.
        scan_packages, skipped_cve_packages = _build_cve_scan_packages(
            packages, venv_pkgs
        )
        skipped_warning = _format_skipped_cve_packages(skipped_cve_packages)
        if skipped_warning:
            print(skipped_warning, file=sys.stderr)
        try:
            all_vulns = scan_vulnerabilities(
                scan_packages,
                cache=cache,
                refresh=args.refresh,
                offline=args.offline,
            )
        except CacheMissError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
            cache.close()
            sys.exit(1)
        cache.store_vulnerabilities(run_id, all_vulns)

        threshold_rank = SEVERITY_RANK.get(args.severity_threshold, 0)
        visible_vulns = [
            v for v in all_vulns if SEVERITY_RANK.get(v.severity, 0) >= threshold_rank
        ]

        print(f"\n=== CVE Scan ({args.severity_threshold}+) ===\n")
        print_cve_table(visible_vulns)

    # --- Usage analysis --------------------------------------------------
    usage_report = None
    if args.usage_analysis:
        if args.source:
            print("\nAnalysing source usage…")
            try:
                _ua_venv = find_venv(args.source)
            except FileNotFoundError:
                _ua_venv = None
            usage_report = analyse_usage(args.source, packages, venv_path=_ua_venv)
            _print_usage_summary(usage_report)
            cache.store_usage_report(run_id, usage_report)
        else:
            print(
                "Note: usage analysis requires a local source directory (--source). "
                "Skipping.",
                file=sys.stderr,
            )

    # --- Impact analysis -------------------------------------------------
    impact_reports: list = []
    if args.impact_analysis:
        if not args.cve_scan:
            print(
                "Note: --impact-analysis requires --cve-scan. Skipping.",
                file=sys.stderr,
            )
        else:
            openai_key = os.environ.get("OPENAI_API_KEY")
            openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
            openai_base = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
            allow_commercial_usage_data = (
                args.allow_commercial_usage_data
                or os.environ.get("CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA", "").lower()
                in {"1", "true", "yes"}
            )
            if not openai_key:
                print(
                    "Error: --impact-analysis requires OPENAI_API_KEY in environment or .env.",
                    file=sys.stderr,
                )
                cache.finish_run(
                    run_id,
                    status="failed",
                    invalidation_reason="missing OPENAI_API_KEY",
                )
                cache.close()
                sys.exit(1)
            elif (
                usage_data_requires_opt_in(openai_base, usage_report)
                and not allow_commercial_usage_data
            ):
                print(
                    "Error: refusing to send source-derived usage-analysis data to a "
                    "hosted commercial LLM endpoint without explicit opt-in. Re-run "
                    "with --allow-commercial-usage-data or set "
                    "CHANGES_AI_ALLOW_COMMERCIAL_USAGE_DATA=1.",
                    file=sys.stderr,
                )
                cache.finish_run(
                    run_id,
                    status="failed",
                    invalidation_reason="commercial usage-data opt-in required",
                )
                cache.close()
                sys.exit(1)
            else:
                if not args.usage_analysis:
                    print(
                        "Warning: --usage-analysis not enabled; impact assessment will run "
                        "without usage intersection, which reduces confidence. "
                        "Re-run with --usage-analysis for a better result.",
                        file=sys.stderr,
                    )
                print("\nRunning LLM impact analysis…")
                try:
                    impact_reports = run_impact_analysis(
                        vulns=all_vulns,
                        usage_report=usage_report,
                        api_key=openai_key,
                        model=openai_model,
                        api_base=openai_base,
                        allow_commercial_usage_data=allow_commercial_usage_data,
                        currency_records=currency_records,
                        github_token=github_token,
                        cache=cache,
                        refresh=args.refresh,
                        offline=args.offline,
                    )
                except CacheMissError as exc:
                    print(f"Error: {exc}", file=sys.stderr)
                    cache.finish_run(
                        run_id, status="failed", invalidation_reason=str(exc)
                    )
                    cache.close()
                    sys.exit(1)
                _print_impact_summary(impact_reports)
                cache.store_impact_reports(run_id, impact_reports)
                if args.output in ("json", "both"):
                    print("\n=== Impact Analysis (JSON) ===\n")
                    print(json.dumps([r.to_dict() for r in impact_reports], indent=2))

    # --- Remediation plan ------------------------------------------------
    if args.plan:
        if not args.impact_analysis:
            print(
                "Error: --plan requires --impact-analysis (no breakage signal available without it).",
                file=sys.stderr,
            )
            cache.finish_run(
                run_id,
                status="failed",
                invalidation_reason="--plan without --impact-analysis",
            )
            cache.close()
            sys.exit(1)
        elif not args.cve_scan:
            # impact_analysis already requires cve_scan, but guard defensively.
            print(
                "Error: --plan requires --cve-scan.",
                file=sys.stderr,
            )
            cache.finish_run(
                run_id, status="failed", invalidation_reason="--plan without --cve-scan"
            )
            cache.close()
            sys.exit(1)
        else:
            # openai_key/model/base are already resolved and validated by the
            # --impact-analysis block above (which --plan requires).
            print("\nRunning remediation planner…")
            try:
                remediation_paths = run_remediation_plan(
                    vulns=all_vulns,
                    impact_reports=impact_reports,
                    api_key=openai_key,
                    model=openai_model,
                    api_base=openai_base,
                    currency_records=currency_records,
                    cache=cache,
                    refresh=args.refresh,
                    offline=args.offline,
                )
            except CacheMissError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                cache.finish_run(run_id, status="failed", invalidation_reason=str(exc))
                cache.close()
                sys.exit(1)
            _print_remediation_plan(remediation_paths, all_vulns)
            cache.store_remediation_paths(run_id, remediation_paths)
            if args.output in ("json", "both"):
                print("\n=== Remediation Plan (JSON) ===\n")
                print(
                    json.dumps(
                        {
                            "remediation_plan": {
                                "paths": [p.to_dict() for p in remediation_paths]
                            }
                        },
                        indent=2,
                    )
                )

    report = cache.get_run_report(run_id)
    if report is not None:
        executive_summary_narrative = _generate_executive_summary_narrative(
            report,
            api_key=_executive_summary_api_key(args.impact_analysis),
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            api_base=os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1"),
            cache=cache,
            refresh=args.refresh,
            offline=args.offline,
        )
        cache.store_run_summary(run_id, executive_summary_narrative)

    scan_report_format = args.format
    report_output_path = _resolve_report_output_path(
        scan_report_format, args.report_output
    )
    if report_output_path is not None:
        report = cache.get_run_report(run_id)
        if report is not None:
            rendered = _render_cached_report(
                report,
                scan_report_format,
                run_id,
                report_template=args.report_template,
            )
            if scan_report_format == "html":
                if not isinstance(rendered, dict):
                    raise RuntimeError(
                        "HTML report rendering did not return an asset bundle"
                    )
                output_path = _write_html_report_output(report_output_path, rendered)
            else:
                content = rendered if isinstance(rendered, bytes) else rendered + "\n"
                output_path = _write_report_output(report_output_path, content)
            print(f"\nReport written to {output_path}")

    # --- Deferred --fail-on exit (after all analysis is complete) --------
    if args.cve_scan and args.fail_on is not None:
        fail_rank = SEVERITY_RANK.get(args.fail_on, 0)
        failing = [
            v for v in all_vulns if SEVERITY_RANK.get(v.severity, 0) >= fail_rank
        ]
        if failing:
            print(
                f"\nFailing: {len(failing)} vulnerability/ies at or above {args.fail_on}.",
                file=sys.stderr,
            )
            cache.finish_run(run_id, status="completed")
            cache.close()
            sys.exit(2)

    cache.finish_run(run_id)
    cache.close()


if __name__ == "__main__":
    main()
