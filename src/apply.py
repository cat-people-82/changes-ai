"""Ecosystem-agnostic remediation apply pipeline.

The rollback contract is intentionally narrow: manifest and lockfile
content are snapshotted and restored on failure, but the Python
environment itself is not snapshotted or restored. If an install command
fails partway through, the environment may need a manual reinstall after
the manifest and lockfile are restored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    from .ecosystem.base import ApplyOutcome, EcosystemAdapter, ManifestInfo
except ImportError:  # pragma: no cover
    from src.ecosystem.base import ApplyOutcome, EcosystemAdapter, ManifestInfo


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


def snapshot(
    manifest: ManifestInfo,
    environment_root: Path | None,
) -> ManifestSnapshot:
    """Capture the manifest and current lockfile content, if present.

    Raises OSError if a file cannot be read; callers should handle this
    before entering the rollback-capable apply pipeline.
    """
    files: dict[Path, str] = {
        manifest.path: manifest.path.read_text(encoding="utf-8")
    }
    if manifest.has_lockfile and manifest.lockfile_path is not None:
        files[manifest.lockfile_path] = manifest.lockfile_path.read_text(
            encoding="utf-8"
        )
    return ManifestSnapshot(files=files, environment_root=environment_root)


def restore(snap: ManifestSnapshot) -> None:
    """Restore every snapshotted file, ignoring removed parent paths."""
    for path, content in snap.files.items():
        try:
            path.write_text(content, encoding="utf-8")
        except FileNotFoundError:
            continue


def apply_remediation(
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    upgrades: list[UpgradeSelection],
    environment_root: Path | None = None,
    *,
    dry_run_only: bool = False,
) -> ApplyResult:
    """Apply upgrades with rollback of manifest and lockfile on failure.

    The environment itself is not snapshotted or restored.
    """
    try:
        snap = snapshot(manifest, environment_root)
    except OSError as exc:
        return ApplyResult(
            success=False,
            dry_run=False,
            upgrades_applied=[],
            files_modified=[],
            install_output="",
            error=f"snapshot failed: {exc}",
        )
    files_modified: list[Path] = []

    ok, err = adapter.dry_run_validate(manifest, upgrades, environment_root)
    if not ok:
        return ApplyResult(
            success=False,
            dry_run=False,
            upgrades_applied=[],
            files_modified=[],
            install_output="",
            error=err,
        )

    if dry_run_only:
        return ApplyResult(
            success=True,
            dry_run=True,
            upgrades_applied=upgrades,
            files_modified=[],
            install_output="",
            error=None,
        )

    try:
        manifest_path = adapter.write_manifest(
            manifest,
            upgrades,
            snap.files[manifest.path],
        )
        files_modified.append(manifest_path)
    except Exception as exc:  # noqa: BLE001
        restore(snap)
        return ApplyResult(
            success=False,
            dry_run=False,
            upgrades_applied=[],
            files_modified=[],
            install_output="",
            error=f"manifest write failed: {exc}",
        )

    if manifest.has_lockfile:
        lock_outcome = adapter.regenerate_lockfile(manifest)
        if not lock_outcome.success:
            restore(snap)
            return ApplyResult(
                success=False,
                dry_run=False,
                upgrades_applied=[],
                files_modified=[],
                install_output=lock_outcome.output,
                error=f"lockfile regeneration failed: {lock_outcome.output}",
            )
        files_modified.extend(lock_outcome.files_modified)

    install_outcome = adapter.install(manifest, upgrades, environment_root)
    if not install_outcome.success:
        restore(snap)
        return ApplyResult(
            success=False,
            dry_run=False,
            upgrades_applied=[],
            files_modified=[],
            install_output=install_outcome.output,
            error=f"install failed: {install_outcome.output}",
        )

    return ApplyResult(
        success=True,
        dry_run=False,
        upgrades_applied=upgrades,
        files_modified=files_modified,
        install_output=install_outcome.output,
        error=None,
    )


__all__ = [
    "ApplyResult",
    "ManifestSnapshot",
    "UpgradeSelection",
    "apply_remediation",
    "restore",
    "snapshot",
]
