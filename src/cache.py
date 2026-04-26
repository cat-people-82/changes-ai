"""SQLite cache and run-artifact storage for Changes AI."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 3
DEFAULT_TTLS = {
    "libraries_io_package": 6 * 60 * 60,
    "libraries_io_dependencies": 24 * 60 * 60,
    "osv_batch": 60 * 60,
    "osv_vuln": 6 * 60 * 60,
    "pypi_package": 6 * 60 * 60,
    "release_notes": 24 * 60 * 60,
    "github_releases": 24 * 60 * 60,
    "llm": 7 * 24 * 60 * 60,
}


class CacheMissError(RuntimeError):
    """Raised when offline mode requires a cache entry that is missing or stale."""


@dataclass
class CacheEntry:
    source: str
    cache_key: str
    created_at: int
    expires_at: int
    payload: Any


def default_cache_path() -> Path:
    env_path = os.environ.get("CHANGES_AI_CACHE_DB")
    if env_path:
        return Path(env_path).expanduser()
    return Path.home() / ".cache" / "changes-ai" / "cache.sqlite"


def _normalise_source_fingerprint(source_fingerprint: str | dict | None) -> str | None:
    if source_fingerprint is None:
        return None
    if isinstance(source_fingerprint, dict):
        return json.dumps(source_fingerprint, sort_keys=True)
    return str(source_fingerprint)


class SQLiteCache:
    """Small SQLite-backed cache for external API responses and run artifacts."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = (
            Path(path).expanduser() if path is not None else default_cache_path()
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def _init_schema(self) -> None:
        with self._lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            current_version = self._schema_version()
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_cache (
                    source TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    source_fingerprint TEXT,
                    invalidation_reason TEXT,
                    PRIMARY KEY (source, cache_key)
                );

                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    locator TEXT NOT NULL,
                    source_fingerprint TEXT,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER,
                    run_fingerprint TEXT,
                    started_at INTEGER NOT NULL,
                    completed_at INTEGER,
                    status TEXT NOT NULL,
                    invalidation_reason TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );

                CREATE TABLE IF NOT EXISTS packages (
                    run_id INTEGER,
                    name TEXT NOT NULL,
                    installed_version TEXT,
                    requirement TEXT,
                    latest_version TEXT,
                    status TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS edges (
                    run_id INTEGER,
                    parent TEXT NOT NULL,
                    child TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS currency_signals (
                    run_id INTEGER,
                    package TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    run_id INTEGER,
                    package TEXT NOT NULL,
                    installed_version TEXT,
                    cve_id TEXT NOT NULL,
                    severity TEXT,
                    payload_json TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS usage_symbols (
                    run_id INTEGER,
                    package TEXT,
                    module TEXT,
                    symbol TEXT,
                    source_file TEXT,
                    line INTEGER,
                    flag TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS impact_reports (
                    run_id INTEGER,
                    package TEXT NOT NULL,
                    installed_version TEXT,
                    candidate_version TEXT,
                    payload_json TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS remediation_paths (
                    run_id INTEGER,
                    path_type TEXT NOT NULL,
                    payload_json TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS run_summaries (
                    run_id INTEGER PRIMARY KEY,
                    narrative TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                );

                CREATE TABLE IF NOT EXISTS llm_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                """
            )
            if current_version == 0:
                self._set_schema_version(SCHEMA_VERSION)
            else:
                self._migrate_schema(current_version)
            self.conn.commit()

    def _schema_version(self) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT value FROM cache_metadata WHERE key = ?",
                ("schema_version",),
            ).fetchone()
            if row is None:
                return 0
            try:
                return int(row["value"])
            except (KeyError, TypeError, ValueError):
                return 0

    def _set_schema_version(self, version: int) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cache_metadata(key, value) VALUES (?, ?)",
                ("schema_version", str(version)),
            )

    def _migrate_schema(self, current_version: int) -> None:
        version = current_version
        while version < SCHEMA_VERSION:
            if version == 1:
                with self._lock:
                    self.conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS currency_signals (
                            run_id INTEGER,
                            package TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            FOREIGN KEY(run_id) REFERENCES runs(id)
                        )
                        """
                    )
                version = 2
                self._set_schema_version(version)
                continue
            if version == 2:
                with self._lock:
                    self.conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS run_summaries (
                            run_id INTEGER PRIMARY KEY,
                            narrative TEXT NOT NULL,
                            FOREIGN KEY(run_id) REFERENCES runs(id)
                        )
                        """
                    )
                version = 3
                self._set_schema_version(version)
                continue
            raise RuntimeError(
                f"Unsupported cache schema migration path from {version}"
            )

    def get(
        self,
        source: str,
        cache_key: str,
        *,
        ttl_seconds: int | None = None,
        refresh: bool = False,
        offline: bool = False,
        source_fingerprint: str | dict | None = None,
    ) -> Any | None:
        if refresh:
            if offline:
                raise CacheMissError(
                    f"Cannot refresh {source}:{cache_key!r} while offline."
                )
            return None

        with self._lock:
            row = self.conn.execute(
                """
                SELECT source, cache_key, payload_json, created_at, expires_at
                       , source_fingerprint
                FROM api_cache
                WHERE source = ? AND cache_key = ?
                """,
                (source, cache_key),
            ).fetchone()
            now = int(time.time())
            if row is None:
                if offline:
                    raise CacheMissError(f"No cached entry for {source}:{cache_key!r}.")
                return None

            expected_fingerprint = _normalise_source_fingerprint(source_fingerprint)
            cached_fingerprint = _normalise_source_fingerprint(
                row["source_fingerprint"]
            )
            if (
                expected_fingerprint is not None
                and cached_fingerprint != expected_fingerprint
            ):
                if offline:
                    raise CacheMissError(
                        f"Cached entry for {source}:{cache_key!r} has a mismatched source fingerprint."
                    )
                self.conn.execute(
                    """
                    UPDATE api_cache
                    SET invalidation_reason = ?
                    WHERE source = ? AND cache_key = ?
                    """,
                    ("source fingerprint changed", source, cache_key),
                )
                self.conn.commit()
                return None

            expires_at = int(row["expires_at"])
            if ttl_seconds is not None:
                expires_at = int(row["created_at"]) + ttl_seconds
            if expires_at < now:
                if offline:
                    raise CacheMissError(
                        f"Cached entry for {source}:{cache_key!r} is stale."
                    )
                return None

            return json.loads(row["payload_json"])

    def set(
        self,
        source: str,
        cache_key: str,
        payload: Any,
        *,
        ttl_seconds: int | None = None,
        source_fingerprint: str | dict | None = None,
    ) -> None:
        now = int(time.time())
        ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTLS.get(source, 3600)
        with self._lock:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO api_cache(
                    source, cache_key, payload_json, created_at, expires_at,
                    source_fingerprint, invalidation_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    source,
                    cache_key,
                    json.dumps(payload, sort_keys=True),
                    now,
                    now + ttl,
                    _normalise_source_fingerprint(source_fingerprint),
                ),
            )
            self.conn.commit()

    def list_entries(self) -> list[CacheEntry]:
        rows = self.conn.execute(
            """
            SELECT source, cache_key, payload_json, created_at, expires_at
            FROM api_cache
            ORDER BY source, cache_key
            """
        ).fetchall()
        return [
            CacheEntry(
                source=row["source"],
                cache_key=row["cache_key"],
                created_at=int(row["created_at"]),
                expires_at=int(row["expires_at"]),
                payload=json.loads(row["payload_json"]),
            )
            for row in rows
        ]

    def clear(self, source: str | None = None) -> int:
        if source:
            cur = self.conn.execute("DELETE FROM api_cache WHERE source = ?", (source,))
        else:
            cur = self.conn.execute("DELETE FROM api_cache")
        self.conn.commit()
        return int(cur.rowcount)

    def start_run(
        self,
        *,
        locator: str,
        source_fingerprint: str | None = None,
        run_fingerprint: str | None = None,
    ) -> int:
        now = int(time.time())
        project = self.conn.execute(
            """
            INSERT INTO projects(locator, source_fingerprint, created_at)
            VALUES (?, ?, ?)
            """,
            (
                locator,
                json.dumps(source_fingerprint, sort_keys=True)
                if isinstance(source_fingerprint, dict)
                else source_fingerprint,
                now,
            ),
        )
        project_id = int(project.lastrowid)
        run = self.conn.execute(
            """
            INSERT INTO runs(project_id, run_fingerprint, started_at, status)
            VALUES (?, ?, ?, ?)
            """,
            (project_id, run_fingerprint, now, "running"),
        )
        self.conn.commit()
        return int(run.lastrowid)

    def finish_run(
        self,
        run_id: int,
        *,
        status: str = "completed",
        invalidation_reason: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            UPDATE runs
            SET completed_at = ?, status = ?, invalidation_reason = ?
            WHERE id = ?
            """,
            (int(time.time()), status, invalidation_reason, run_id),
        )
        self.conn.commit()

    def store_packages(self, run_id: int, mapping: list[dict]) -> None:
        self.conn.executemany(
            """
            INSERT INTO packages(
                run_id, name, installed_version, requirement, latest_version, status
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    row.get("name"),
                    row.get("installed"),
                    row.get("requirement"),
                    row.get("latest"),
                    row.get("status"),
                )
                for row in mapping
            ],
        )
        self.conn.commit()

    def get_packages_for_run(self, run_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT name, installed_version, requirement, latest_version, status
            FROM packages
            WHERE run_id = ?
            ORDER BY name
            """,
            (run_id,),
        ).fetchall()
        return [
            {
                "name": row["name"],
                "installed": row["installed_version"],
                "requirement": row["requirement"],
                "latest": row["latest_version"],
                "status": row["status"],
            }
            for row in rows
        ]

    def latest_run_id(self) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM runs ORDER BY started_at DESC, id DESC LIMIT 1"
        ).fetchone()
        return int(row["id"]) if row else None

    def get_run_metadata(self, run_id: int) -> dict | None:
        row = self.conn.execute(
            """
            SELECT runs.id, runs.run_fingerprint, runs.started_at, runs.completed_at,
                   runs.status, runs.invalidation_reason, projects.locator,
                   projects.source_fingerprint
            FROM runs
            LEFT JOIN projects ON projects.id = runs.project_id
            WHERE runs.id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        source_fingerprint = row["source_fingerprint"]
        source_metadata = {}
        if source_fingerprint:
            try:
                parsed = json.loads(source_fingerprint)
                if isinstance(parsed, dict):
                    source_metadata = parsed
            except json.JSONDecodeError:
                source_metadata = {"fingerprint": source_fingerprint}

        return {
            "id": row["id"],
            "locator": row["locator"],
            "source_fingerprint": row["source_fingerprint"],
            "source_metadata": source_metadata,
            "run_fingerprint": row["run_fingerprint"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "status": row["status"],
            "invalidation_reason": row["invalidation_reason"],
        }

    def store_vulnerabilities(self, run_id: int, records: list) -> None:
        self.conn.executemany(
            """
            INSERT INTO vulnerabilities(
                run_id, package, installed_version, cve_id, severity, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    record.package,
                    record.installed_version,
                    record.cve_id,
                    record.severity,
                    json.dumps(
                        {
                            "affected_ranges": record.affected_ranges,
                            "fixed_versions": record.fixed_versions,
                        },
                        sort_keys=True,
                    ),
                )
                for record in records
            ],
        )
        self.conn.commit()

    def get_vulnerabilities_for_run(self, run_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT package, installed_version, cve_id, severity, payload_json
            FROM vulnerabilities
            WHERE run_id = ?
            ORDER BY severity, package, cve_id
            """,
            (run_id,),
        ).fetchall()
        records = []
        for row in rows:
            payload = json.loads(row["payload_json"] or "{}")
            records.append(
                {
                    "package": row["package"],
                    "installed_version": row["installed_version"],
                    "cve_id": row["cve_id"],
                    "severity": row["severity"],
                    "affected_ranges": payload.get("affected_ranges", []),
                    "fixed_versions": payload.get("fixed_versions", []),
                }
            )
        return records

    def store_usage_report(self, run_id: int, report: Any) -> None:
        rows = []
        for record in report.records:
            rows.append(
                (
                    run_id,
                    record.package,
                    record.module,
                    record.symbol,
                    record.source_file,
                    record.line,
                    None,
                )
            )
        for unresolved in report.unresolved:
            rows.append(
                (
                    run_id,
                    unresolved.package,
                    None,
                    None,
                    unresolved.source_file,
                    unresolved.line,
                    unresolved.flag,
                )
            )
        self.conn.executemany(
            """
            INSERT INTO usage_symbols(
                run_id, package, module, symbol, source_file, line, flag
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()

    def store_currency_records(self, run_id: int, records: list[dict]) -> None:
        self.conn.executemany(
            """
            INSERT INTO currency_signals(run_id, package, payload_json)
            VALUES (?, ?, ?)
            """,
            [
                (
                    run_id,
                    record.get("package"),
                    json.dumps(record, sort_keys=True),
                )
                for record in records
            ],
        )
        self.conn.commit()

    def get_currency_for_run(self, run_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT payload_json
            FROM currency_signals
            WHERE run_id = ?
            ORDER BY package
            """,
            (run_id,),
        ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def store_dependency_edges(self, run_id: int, edges: list[dict]) -> None:
        self.conn.executemany(
            """
            INSERT INTO edges(run_id, parent, child)
            VALUES (?, ?, ?)
            """,
            [(run_id, edge.get("parent"), edge.get("child")) for edge in edges],
        )
        self.conn.commit()

    def get_dependency_graph_for_run(self, run_id: int) -> dict:
        rows = self.conn.execute(
            """
            SELECT parent, child
            FROM edges
            WHERE run_id = ?
            ORDER BY parent, child
            """,
            (run_id,),
        ).fetchall()
        return {
            "edges": [
                {
                    "parent": row["parent"],
                    "child": row["child"],
                }
                for row in rows
            ]
        }

    def get_usage_for_run(self, run_id: int) -> dict:
        rows = self.conn.execute(
            """
            SELECT package, module, symbol, source_file, line, flag
            FROM usage_symbols
            WHERE run_id = ?
            ORDER BY package, source_file, line
            """,
            (run_id,),
        ).fetchall()
        records = []
        unresolved = []
        for row in rows:
            item = {
                "package": row["package"] or "",
                "module": row["module"],
                "symbol": row["symbol"],
                "source_file": row["source_file"],
                "line": row["line"],
                "flag": row["flag"],
            }
            if row["flag"]:
                unresolved.append(item)
            else:
                records.append(item)
        return {"records": records, "unresolved": unresolved}

    def store_impact_reports(self, run_id: int, reports: list) -> None:
        self.conn.executemany(
            """
            INSERT INTO impact_reports(
                run_id, package, installed_version, candidate_version, payload_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    report.package,
                    report.installed_version,
                    report.candidate_version,
                    json.dumps(report.to_dict(), sort_keys=True),
                )
                for report in reports
            ],
        )
        self.conn.commit()

    def get_impact_reports_for_run(self, run_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT payload_json
            FROM impact_reports
            WHERE run_id = ?
            ORDER BY package, candidate_version
            """,
            (run_id,),
        ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def store_remediation_paths(self, run_id: int, paths: list) -> None:
        self.conn.executemany(
            """
            INSERT INTO remediation_paths(run_id, path_type, payload_json)
            VALUES (?, ?, ?)
            """,
            [
                (
                    run_id,
                    path.path_type,
                    json.dumps(path.to_dict(), sort_keys=True),
                )
                for path in paths
            ],
        )
        self.conn.commit()

    def get_remediation_paths_for_run(self, run_id: int) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT payload_json
            FROM remediation_paths
            WHERE run_id = ?
            ORDER BY path_type
            """,
            (run_id,),
        ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def store_run_summary(self, run_id: int, narrative: str) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO run_summaries(run_id, narrative)
            VALUES (?, ?)
            """,
            (run_id, narrative),
        )
        self.conn.commit()

    def get_run_summary_for_run(self, run_id: int) -> str | None:
        row = self.conn.execute(
            """
            SELECT narrative
            FROM run_summaries
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row["narrative"])

    def get_run_report(self, run_id: int) -> dict | None:
        metadata = self.get_run_metadata(run_id)
        if metadata is None:
            return None
        return {
            "run": metadata,
            "packages": self.get_packages_for_run(run_id),
            "currency": self.get_currency_for_run(run_id),
            "graph": self.get_dependency_graph_for_run(run_id),
            "vulnerabilities": self.get_vulnerabilities_for_run(run_id),
            "usage": self.get_usage_for_run(run_id),
            "impact_reports": self.get_impact_reports_for_run(run_id),
            "remediation_paths": self.get_remediation_paths_for_run(run_id),
            "executive_summary": {
                "narrative": self.get_run_summary_for_run(run_id),
            },
        }
