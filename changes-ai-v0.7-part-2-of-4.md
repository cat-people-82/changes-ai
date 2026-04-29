# Changes AI v0.7 — Part 2 of 4

## OSV Per-Ecosystem Routing & Apply Pipeline (Python)

This is part 2 of the v0.7 release. **Do not start this part until Part 1
is complete and the test suite passes unchanged.**

- Part 1: Ecosystem adapter protocol + Python migration. ✅ done.
- **Part 2 (this document):** OSV per-ecosystem routing + apply pipeline
  for Python.
- Part 3: NPM adapter + JS/TS usage analyser.
- Part 4: Interactive editor + CLI wiring for `--apply` / `--auto-apply` /
  `--ecosystem`.

---

## Goal of Part 2

Two ecosystem-agnostic foundations that Part 3 (NPM) and Part 4 (editor)
both depend on:

1. **OSV ecosystem routing** so Part 3 can scan NPM packages without
   another sweep through `vulnerability.py`.
2. **Apply pipeline** so Part 4's interactive editor has a working backend
   to call. Apply pipeline is a single orchestrator
   (`apply_remediation`) plus the `PythonAdapter` write/install/dry-run
   methods that were stubbed in Part 1.

After this part, an internal API call to `apply_remediation(adapter,
manifest, upgrades)` against a Python project performs the full snapshot →
validate → write → regenerate-lockfile → install → rollback-on-failure
sequence. No CLI flag exposes it yet — that's Part 4.

---

## Context

Read these files before writing any plan or code:

- `src/vulnerability.py` — `OSVClient`, `ecosystem` field at lines ~125
  and ~374.
- `src/ecosystem/python_adapter.py` — the apply methods stubbed in Part 1.
- `src/ecosystem/base.py` — `ManifestInfo`, `ApplyOutcome`.
- `src/changes_ai.py` — note where `OSVClient` is instantiated and called;
  these calls need to pass `adapter.osv_ecosystem`.
- `tests/test_smoke.py` — extend with new tests; do not duplicate
  existing fixtures.
- `pyproject.toml`.

---

## Constraints

- New module: `src/apply.py`. New tests go in `tests/test_smoke.py`.
- All new tests must be deterministic. No network calls, no LLM calls.
  Mock HTTP for the OSV test; mock subprocess for install / lockfile tests.
- All file modification must be preceded by a snapshot. Every write path
  must be able to restore the pre-modification state on failure.
- `uv.lock` and `poetry.lock` are not hand-edited — regeneration shells
  out to `uv lock` / `poetry lock`. If the relevant tool is missing,
  `regenerate_lockfile` returns
  `ApplyOutcome(success=False, output="<tool> not found on PATH; ...")`
  rather than crashing.
- Backward compatibility: existing CLI behaviour is unchanged. Apply
  pipeline is reachable only via direct API call until Part 4 wires the
  CLI flags.
- All changes must pass `pytest tests/` before this part is marked done.

---

## Task 2.1 — OSV per-ecosystem routing

**File:** `src/vulnerability.py`

The OSV client currently hardcodes `"ecosystem": "PyPI"` at line ~125
when building the request body, and filters on
`"ecosystem") == "PyPI"` at line ~374 when parsing the response. Both
must accept the ecosystem from the caller.

Add an `ecosystem: str = "PyPI"` parameter to:

- `OSVClient.query_packages` (or wherever the query body is built) — the
  parameter feeds the value placed in `{"package": {..., "ecosystem":
  <value>}}`.
- The result-filtering logic that splits affected entries by ecosystem.

Default value `"PyPI"` keeps every existing caller working without
modification. Update the caller in `src/changes_ai.py`'s `main()` to pass
`adapter.osv_ecosystem` explicitly.

If `OSVClient` is instantiated with a default ecosystem at construction
time (via `__init__`), prefer that pattern over passing the ecosystem to
each method call — the client almost always queries one ecosystem per
run. Both forms should still accept the ecosystem at the call site as an
override, in case an adapter ever needs to query multiple ecosystems in
one run.

**Tests:**

- `test_osv_client_uses_ecosystem_parameter` — mock the HTTP layer with
  a recording session, call `OSVClient(...).query_packages([...],
  ecosystem="npm")`, assert the recorded request body contains
  `{"package": {"name": ..., "ecosystem": "npm"}}`.
- `test_osv_client_default_ecosystem_pypi_unchanged` — call without
  specifying ecosystem, assert request body uses `"PyPI"`. This is the
  guard against accidentally breaking Python users.
- `test_osv_response_filtering_respects_ecosystem` — feed a mocked
  response containing entries from both `PyPI` and `npm` ecosystems; with
  `ecosystem="npm"`, assert only the `npm` entries are returned.

---

## Task 2.2 — Apply pipeline

### 2.2a — Module skeleton

**File:** `src/apply.py` (new)

The apply module is ecosystem-agnostic. It receives an
`EcosystemAdapter` and a `ManifestInfo` and orchestrates the lifecycle.
All ecosystem-specific work is delegated to the adapter.

```python
from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path

from src.ecosystem.base import EcosystemAdapter, ManifestInfo, ApplyOutcome


@dataclass
class UpgradeSelection:
    package: str
    from_version: str
    to_version: str
    fixes_cves: list[str] = field(default_factory=list)


@dataclass
class ManifestSnapshot:
    files: dict[Path, str]
    environment_root: Path | None


@dataclass
class ApplyResult:
    success: bool
    dry_run: bool
    upgrades_applied: list[UpgradeSelection]
    files_modified: list[Path]
    install_output: str
    error: str | None
```

### 2.2b — Snapshot and restore

```python
def snapshot(
    manifest: ManifestInfo,
    environment_root: Path | None,
) -> ManifestSnapshot:
    """Capture the manifest and (if present) lockfile content."""
    files: dict[Path, str] = {}
    files[manifest.path] = manifest.path.read_text()
    if manifest.has_lockfile and manifest.lockfile_path is not None:
        files[manifest.lockfile_path] = manifest.lockfile_path.read_text()
    return ManifestSnapshot(files=files, environment_root=environment_root)


def restore(snap: ManifestSnapshot) -> None:
    """Write each captured file back. Ignore files that no longer exist."""
    for path, content in snap.files.items():
        try:
            path.write_text(content)
        except FileNotFoundError:
            continue
```

> **Rationale for not snapshotting the venv:** restoring a venv reliably
> requires either freezing pip output before-and-after (slow, error-prone
> on uv/poetry environments) or filesystem snapshots (out of scope). The
> rollback contract is therefore: *manifest and lockfile are guaranteed to
> be restored on failure; the environment is left in whatever state the
> failed install command produced.* The user is expected to re-run install
> manually if needed. Document this in the `apply_remediation` docstring.

### 2.2c — Orchestrator

```python
def apply_remediation(
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    upgrades: list[UpgradeSelection],
    environment_root: Path | None = None,
    *,
    dry_run_only: bool = False,
) -> ApplyResult:
    """Snapshot → validate → write manifest → regenerate lockfile → install.

    On any failure after step 1, the snapshot is restored before the
    failure is returned. The environment (venv contents) is not snapshotted
    or restored — see module docstring.
    """
    snap = snapshot(manifest, environment_root)
    files_modified: list[Path] = []

    ok, err = adapter.dry_run_validate(manifest, upgrades, environment_root)
    if not ok:
        return ApplyResult(
            success=False, dry_run=False,
            upgrades_applied=[], files_modified=[],
            install_output="", error=err,
        )

    if dry_run_only:
        return ApplyResult(
            success=True, dry_run=True,
            upgrades_applied=upgrades, files_modified=[],
            install_output="", error=None,
        )

    try:
        manifest_path = adapter.write_manifest(
            manifest, upgrades, snap.files[manifest.path],
        )
        files_modified.append(manifest_path)
    except Exception as exc:
        restore(snap)
        return ApplyResult(
            success=False, dry_run=False,
            upgrades_applied=[], files_modified=[],
            install_output="", error=f"manifest write failed: {exc}",
        )

    if manifest.has_lockfile:
        lock_outcome = adapter.regenerate_lockfile(manifest)
        if not lock_outcome.success:
            restore(snap)
            return ApplyResult(
                success=False, dry_run=False,
                upgrades_applied=[], files_modified=[],
                install_output=lock_outcome.output,
                error=f"lockfile regeneration failed: {lock_outcome.output}",
            )
        files_modified.extend(lock_outcome.files_modified)

    install_outcome = adapter.install(manifest, upgrades, environment_root)
    if not install_outcome.success:
        restore(snap)
        return ApplyResult(
            success=False, dry_run=False,
            upgrades_applied=[], files_modified=[],
            install_output=install_outcome.output,
            error=f"install failed: {install_outcome.output}",
        )

    return ApplyResult(
        success=True, dry_run=False,
        upgrades_applied=upgrades, files_modified=files_modified,
        install_output=install_outcome.output, error=None,
    )
```

### 2.2d — PythonAdapter apply methods

**File:** `src/ecosystem/python_adapter.py`

Replace the `NotImplementedError` stubs from Part 1 with working
implementations.

**`write_manifest`:**

Routes by `manifest.file_type`:

- `"pip"` → `_write_requirements_txt`. Walks the original content line by
  line, identifies lines beginning with each upgrade's package name
  (case-insensitive, normalise hyphens↔underscores), rewrites the version
  specifier to `==<to_version>`. Preserves all other lines verbatim
  (comments, blank lines, `-r` includes, options like `--index-url`).
  Atomic write via `<path>.tmp` then `os.replace`.
- `"pyproject"` → `_write_pyproject_toml`. Use regex to locate and
  rewrite version strings in both `[project.dependencies]` (PEP 621) and
  `[tool.poetry.dependencies]` sections. Do not parse the full TOML
  structure — a regex rewrite preserves comments and formatting that
  `tomllib` → re-serialise would destroy. Atomic write.

In both writers, normalise the package name from each `UpgradeSelection`
(`name.lower().replace("_", "-")`) and match against a similarly
normalised key extracted from each line. Returns the path written.

**`regenerate_lockfile`:**

```python
def regenerate_lockfile(self, manifest):
    if not manifest.has_lockfile or manifest.lockfile_type is None:
        return ApplyOutcome(success=True, output="no lockfile present", files_modified=[])

    if manifest.lockfile_type == "uv_lockfile":
        return self._run_lock_tool("uv", ["lock"], manifest)
    if manifest.lockfile_type == "poetry_lockfile":
        return self._run_lock_tool("poetry", ["lock", "--no-update"], manifest)
    return ApplyOutcome(
        success=False,
        output=f"unknown lockfile type: {manifest.lockfile_type}",
        files_modified=[],
    )

def _run_lock_tool(self, tool: str, args: list[str], manifest) -> ApplyOutcome:
    import shutil, subprocess
    if shutil.which(tool) is None:
        return ApplyOutcome(
            success=False,
            output=(
                f"{tool} not found on PATH. Install {tool} or run "
                f"'{tool} {' '.join(args)}' manually before deploying."
            ),
            files_modified=[],
        )
    cwd = manifest.path.parent
    result = subprocess.run(
        [tool, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ApplyOutcome(
            success=False,
            output=(result.stderr or result.stdout or f"{tool} exited {result.returncode}").strip(),
            files_modified=[],
        )
    return ApplyOutcome(
        success=True,
        output=result.stdout,
        files_modified=[manifest.lockfile_path] if manifest.lockfile_path else [],
    )
```

**`dry_run_validate`:**

```python
def dry_run_validate(self, manifest, upgrades, environment_root):
    import shutil, subprocess
    pip_cmd = self._resolve_pip(environment_root)
    if not pip_cmd:
        return False, "pip not found on PATH or in venv"
    pkg_args = [f"{u.package}=={u.to_version}" for u in upgrades]
    result = subprocess.run(
        pip_cmd + ["install", "--dry-run", "--no-deps", *pkg_args],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "pip dry-run failed").strip()
    return True, ""
```

> **Why `--no-deps`:** full transitive dry-run via pip is slow (10–30s on
> large projects) and not needed at this stage — the editor's local
> constraint check (Part 4) catches the obvious cases in real time, and
> the lockfile regeneration step is the proper resolver gate. The
> dry-run here is a sanity check that each upgrade target version exists
> on PyPI.

**`install`:**

```python
def install(self, manifest, upgrades, environment_root):
    import subprocess
    pip_cmd = self._resolve_pip(environment_root)
    if not pip_cmd:
        return ApplyOutcome(
            success=False, output="pip not found on PATH or in venv",
            files_modified=[],
        )
    pkg_args = [f"{u.package}=={u.to_version}" for u in upgrades]
    result = subprocess.run(
        pip_cmd + ["install", *pkg_args],
        capture_output=True, text=True, check=False,
    )
    return ApplyOutcome(
        success=(result.returncode == 0),
        output=(result.stdout or "") + (result.stderr or ""),
        files_modified=[],
    )

def _resolve_pip(self, environment_root: Path | None) -> list[str] | None:
    """Detection order: <venv>/bin/uv → <venv>/bin/pip → PATH pip."""
    import shutil
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
```

### 2.2e — Tests

All new tests in `tests/test_smoke.py`. Required cases:

- `test_apply_python_writes_requirements_preserving_comments` — `tmp_path`
  with a `requirements.txt` that includes comments, blank lines, a
  `-r other.txt` include, and three packages (two upgraded, one not).
  Call `PythonAdapter().write_manifest`. Assert the output preserves
  every non-upgraded line and that the two upgraded packages have
  `==<to_version>` specifiers. Asserts that the `-r other.txt` include
  is preserved.
- `test_apply_python_writes_pyproject_preserving_formatting` — same
  shape for `pyproject.toml`. Assert PEP 621 dependencies under
  `[project.dependencies]` are rewritten and surrounding comments,
  indentation, and key ordering are preserved.
- `test_apply_snapshot_restore_round_trip` — write a manifest, take a
  snapshot, overwrite with different content, call `restore`, assert
  original content is back.
- `test_apply_dry_run_failure_does_not_write_manifest` — monkeypatch
  `PythonAdapter.dry_run_validate` to return `(False, "conflict")`.
  Call `apply_remediation`. Assert manifest file content on disk is
  unchanged from the original.
- `test_apply_install_failure_restores_snapshot` — monkeypatch `install`
  to return `ApplyOutcome(success=False, ...)`. Assert the manifest
  file contains the original content after the call returns.
- `test_apply_lockfile_regeneration_failure_restores_snapshot` —
  monkeypatch `regenerate_lockfile` to return failure. Assert manifest
  is restored.
- `test_apply_lockfile_regeneration_returns_clear_error_when_uv_missing` —
  monkeypatch `shutil.which` to return `None` for `"uv"`. Call
  `regenerate_lockfile` on a `ManifestInfo` with `lockfile_type=
  "uv_lockfile"`. Assert the returned `ApplyOutcome` has
  `success=False` and `"uv not found on PATH"` in `output`.

---

## Definition of Done — Part 2

- [ ] `pytest tests/` passes with zero failures and zero errors.
- [ ] All v0.6 CLI flags still behave identically. No user-visible
  change yet (apply pipeline is API-only until Part 4).
- [ ] `OSVClient` accepts an `ecosystem` parameter; default `"PyPI"`
  preserves existing Python behaviour. The caller in `main()` passes
  `adapter.osv_ecosystem`.
- [ ] `src/apply.py` exists and exports `apply_remediation`,
  `UpgradeSelection`, `ManifestSnapshot`, `ApplyResult`, `snapshot`,
  `restore`.
- [ ] `PythonAdapter` no longer raises `NotImplementedError` for
  `write_manifest`, `regenerate_lockfile`, `install`, or
  `dry_run_validate`.
- [ ] A direct API call —
  ```python
  from src.apply import apply_remediation, UpgradeSelection
  from src.ecosystem import REGISTRY
  adapter = REGISTRY["python"]
  manifest = adapter.find_manifest(Path("./test-project"))
  apply_remediation(adapter, manifest, [UpgradeSelection(...)], dry_run_only=True)
  ```
  succeeds against a project with a `requirements.txt`.
- [ ] If `apply_remediation` is called and the install step fails, the
  manifest file is restored to its original content on disk.
- [ ] No CHANGELOG entry yet — Part 4 writes the consolidated v0.7.0
  entry.
