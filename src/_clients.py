from __future__ import annotations

"""LibrariesIOClient, version-mapping helpers and related utilities.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import hashlib
import json
import re
import sys
import time
from typing import Optional

import requests

try:
    from .cache import SQLiteCache
except ImportError:  # pragma: no cover
    from src.cache import SQLiteCache


# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
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
    from concurrent.futures import ThreadPoolExecutor

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


def _build_mapping_from_currency_records(
    packages: dict,
    currency_records: list,
    installed_versions: dict | None = None,
) -> list[dict]:
    _norm = lambda n: n.lower().replace("_", "-")
    installed_lookup = {_norm(k): v for k, v in (installed_versions or {}).items()}
    by_name: dict[str, dict] = {}
    for record in currency_records:
        if hasattr(record, "__dict__"):
            payload = dict(record.__dict__)
        else:
            payload = dict(record)
        package = payload.get("package")
        if package:
            by_name[_norm(package)] = payload

    mapping: list[dict] = []
    for name, requirement in packages.items():
        payload = by_name.get(_norm(name), {})
        installed = installed_lookup.get(_norm(name)) or _concrete_version(requirement)
        latest = payload.get("latest_version")
        if installed and latest:
            status = "up-to-date" if installed == latest else "outdated"
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
    return mapping
