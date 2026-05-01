from __future__ import annotations

"""Dependency-file parsers and virtual-environment reader.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import re
import sys
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


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


def _load_yaml_module():
    """Return the optional PyYAML module when available."""
    try:
        import yaml
    except ImportError:
        return None
    return yaml


# ---------------------------------------------------------------------------
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
        yaml = _load_yaml_module()
        if yaml is None:
            print(
                "Warning: PyYAML not available – falling back to line-based environment.yml parsing.",
                file=sys.stderr,
            )
            return DependencyParser._parse_conda_environment_yml_fallback(content)

        try:
            data = yaml.safe_load(content) or {}
        except Exception as exc:  # noqa: BLE001
            print(
                f"Warning: Failed to parse environment.yml as YAML: {exc}. Falling back to line-based parser.",
                file=sys.stderr,
            )
            return DependencyParser._parse_conda_environment_yml_fallback(content)

        dependencies = data.get("dependencies")
        if not isinstance(dependencies, list):
            return {}

        packages: dict = {}
        for entry in dependencies:
            if isinstance(entry, str):
                name, spec_str = DependencyParser._parse_conda_dependency_entry(entry)
                if name:
                    packages[name] = spec_str
                continue
            if isinstance(entry, dict):
                pip_entries = entry.get("pip")
                if not isinstance(pip_entries, list):
                    continue
                for pip_entry in pip_entries:
                    if not isinstance(pip_entry, str):
                        continue
                    parsed = DependencyParser._parse_requirement_entry(pip_entry)
                    if parsed is None:
                        continue
                    name, spec_str = parsed
                    packages[name] = spec_str
        return packages

    @staticmethod
    def _parse_conda_dependency_entry(entry: str) -> tuple[str | None, str | None]:
        """Parse one conda dependency string into ``(name, specifier)``."""
        entry = entry.split("#")[0].strip()
        if not entry:
            return None, None

        if "::" in entry:
            entry = entry.split("::", 1)[1].strip()

        conda_match = re.match(
            r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(.*)$",
            entry,
        )
        if not conda_match:
            return None, None

        name = conda_match.group(1)
        spec_str = conda_match.group(2).strip()
        if spec_str.startswith("=") and not spec_str.startswith(
            ("==", ">=", "<=", "!=", "~=")
        ):
            spec_str = f"=={spec_str[1:]}"
        return name, spec_str if spec_str else None

    @staticmethod
    def _parse_conda_environment_yml_fallback(content: str) -> dict:
        """Parse a Conda ``environment.yml`` without requiring PyYAML."""
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

            name, spec_str = DependencyParser._parse_conda_dependency_entry(entry)
            if not name:
                continue
            packages[name] = spec_str

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
