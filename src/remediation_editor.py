from __future__ import annotations

import difflib
import os
import shutil
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from src.apply import ApplyResult, UpgradeSelection, apply_remediation, restore, snapshot
from src.ecosystem.base import EcosystemAdapter, ManifestInfo
from src.remediation import _build_planning_context, _compute_exposure_score, _confidence_min, _delta_rank

_RESET = "\033[0m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[0;33m"
_BLUE = "\033[0;34m"
_RED = "\033[0;31m"
_PATH_LABEL = {
    "minimum_breakage": "Minimum Breakage",
    "maximum_coverage": "Maximum Coverage",
    "balanced": "Balanced",
}


@dataclass
class EditorState:
    all_paths: list
    all_impact_reports: list
    all_vulns: list
    selected_path_type: str
    selection: dict[str, UpgradeSelection]
    context: dict


@dataclass
class EditorResult:
    action: str
    selection: list[UpgradeSelection]
    apply_result: ApplyResult | None


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def _delta_kind(from_version: str, to_version: str) -> str:
    def parts(value: str) -> tuple[int, int, int] | None:
        nums = []
        for part in value.split(".", 2):
            if part.isdigit():
                nums.append(int(part))
            else:
                digits = "".join(ch for ch in part if ch.isdigit())
                nums.append(int(digits) if digits else 0)
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums[:3])

    left = parts(from_version)
    right = parts(to_version)
    if left is None or right is None:
        return "unknown"
    if left[0] != right[0]:
        return "major"
    if left[1] != right[1]:
        return "minor"
    if left[2] != right[2]:
        return "patch"
    return "patch"


def _selection_list(state: EditorState) -> list[UpgradeSelection]:
    return list(state.selection.values())


def _base_selection_for_path(state: EditorState, path_type: str) -> dict[str, UpgradeSelection]:
    path = next((item for item in state.all_paths if item.path_type == path_type), None)
    if path is None:
        return {}
    return {
        _norm(upgrade.package): UpgradeSelection(
            package=upgrade.package,
            from_version=upgrade.from_version,
            to_version=upgrade.to_version,
            fixes_cves=list(upgrade.fixes_cves),
        )
        for upgrade in path.upgrades
    }


def _impact_lookup(state: EditorState) -> dict[tuple[str, str, str], object]:
    return {
        (_norm(report.package), report.installed_version, report.candidate_version): report
        for report in state.all_impact_reports
    }


def _report_for_selection(
    state: EditorState,
    upgrade: UpgradeSelection,
    lookup: dict | None = None,
):
    if lookup is None:
        lookup = _impact_lookup(state)
    return lookup.get(
        (_norm(upgrade.package), upgrade.from_version, upgrade.to_version)
    )


def recalculate_scores(state: EditorState) -> tuple[float, float, str]:
    resolved = sorted(
        {
            cve
            for upgrade in state.selection.values()
            for cve in (upgrade.fixes_cves or [])
        }
    )
    no_fix = sorted({v.cve_id for v in state.all_vulns if not getattr(v, "fixed_versions", [])})
    all_cves = set(state.context.get("all_cves") or {v.cve_id for v in state.all_vulns})
    unresolved = sorted(all_cves - set(resolved) - set(no_fix))
    severity_map = state.context.get("severity_map") or {v.cve_id: v.severity for v in state.all_vulns}
    total_weight = state.context.get("total_weight")
    if total_weight is None:
        context = _build_planning_context(state.all_vulns, state.all_impact_reports)
        total_weight = context["total_weight"]

    breakage_scores: list[float] = []
    confidence_labels: list[str] = []
    lookup = _impact_lookup(state)
    for upgrade in state.selection.values():
        report = _report_for_selection(state, upgrade, lookup)
        if report is None:
            continue
        breakage_scores.append(float(report.breakage_score))
        confidence_labels.append(report.confidence)

    exposure = _compute_exposure_score(unresolved, no_fix, severity_map, total_weight)
    return (
        round(exposure, 3),
        round(max(breakage_scores, default=0.0), 3),
        _confidence_min(confidence_labels),
    )


def _parse_version_triplet(version: str) -> tuple[int, int, int] | None:
    parts = version.split(".", 2)
    values: list[int] = []
    for part in parts:
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            return None
        values.append(int(digits))
    while len(values) < 3:
        values.append(0)
    return tuple(values[:3])


def _version_satisfies(candidate: str, requirement: str) -> bool:
    candidate_triplet = _parse_version_triplet(candidate)
    if candidate_triplet is None:
        return True
    for raw_part in requirement.replace(",", " ").split():
        part = raw_part.strip()
        if not part:
            continue
        if part == "*":
            continue
        if part.startswith("=="):
            fixed = _parse_version_triplet(part[2:])
            if fixed is not None and candidate_triplet != fixed:
                return False
        elif part.startswith(">="):
            lower = _parse_version_triplet(part[2:])
            if lower is not None and candidate_triplet < lower:
                return False
        elif part.startswith("<="):
            upper = _parse_version_triplet(part[2:])
            if upper is not None and candidate_triplet > upper:
                return False
        elif part.startswith(">"):
            lower = _parse_version_triplet(part[1:])
            if lower is not None and candidate_triplet <= lower:
                return False
        elif part.startswith("<"):
            upper = _parse_version_triplet(part[1:])
            if upper is not None and candidate_triplet >= upper:
                return False
        elif part.startswith("~="):
            # Compatible release: ~=X.Y.Z means >=X.Y.Z, ==X.Y.*
            lower = _parse_version_triplet(part[2:])
            if lower is not None:
                if candidate_triplet < lower:
                    return False
                upper = (lower[0], lower[1] + 1, 0)
                if candidate_triplet >= upper:
                    return False
        elif part.startswith("^"):
            lower = _parse_version_triplet(part[1:])
            if lower is not None:
                if candidate_triplet < lower:
                    return False
                upper = (lower[0] + 1, 0, 0) if lower[0] > 0 else (0, lower[1] + 1, 0)
                if candidate_triplet >= upper:
                    return False
        elif part.startswith("~"):
            lower = _parse_version_triplet(part[1:])
            if lower is not None:
                if candidate_triplet < lower:
                    return False
                upper = (lower[0], lower[1] + 1, 0)
                if candidate_triplet >= upper:
                    return False
        else:
            exact = _parse_version_triplet(part)
            if exact is not None and candidate_triplet != exact:
                return False
    return True


def check_constraints(
    state: EditorState,
    proposed_selection: dict[str, UpgradeSelection],
) -> list[str]:
    messages: list[str] = []
    reports = state.context.get("reports") or {}
    for upgrade in proposed_selection.values():
        report_entry = None
        key = (_norm(upgrade.package), upgrade.from_version, upgrade.to_version)
        if key in reports:
            report_entry = reports[key]
        else:
            for entry_key, entry in reports.items():
                if (
                    isinstance(entry_key, tuple)
                    and len(entry_key) == 3
                    and entry_key[0] == _norm(upgrade.package)
                    and entry_key[2] == upgrade.to_version
                ):
                    report_entry = entry
                    break
        if report_entry is None:
            continue

        report_obj = report_entry.get("report") if isinstance(report_entry, dict) else report_entry
        dependency_constraints = {}
        if isinstance(report_entry, dict):
            dependency_constraints = report_entry.get("dependency_constraints") or report_entry.get("dependencies") or {}
        if not dependency_constraints and report_obj is not None:
            dependency_constraints = getattr(report_obj, "dependency_constraints", None) or getattr(report_obj, "dependencies", None) or {}

        for dep_name, requirement in (dependency_constraints or {}).items():
            selected = proposed_selection.get(_norm(dep_name))
            if selected is None or not requirement:
                continue
            if not _version_satisfies(selected.to_version, str(requirement)):
                messages.append(
                    f"{upgrade.package} {upgrade.to_version} requires {dep_name}{requirement} "
                    f"but {dep_name} is pinned at {selected.to_version} in this selection"
                )
    return messages


def available_upgrades(state: EditorState) -> list[UpgradeSelection]:
    severity_map = state.context.get("severity_map") or {}
    current = {_norm(name) for name in state.selection}
    seen: set[tuple[str, str]] = set()
    items: list[UpgradeSelection] = []
    for path in state.all_paths:
        if path.path_type == state.selected_path_type:
            continue
        for upgrade in path.upgrades:
            norm_name = _norm(upgrade.package)
            key = (norm_name, upgrade.to_version)
            if norm_name in current or key in seen:
                continue
            seen.add(key)
            items.append(
                UpgradeSelection(
                    package=upgrade.package,
                    from_version=upgrade.from_version,
                    to_version=upgrade.to_version,
                    fixes_cves=list(upgrade.fixes_cves),
                )
            )

    lookup = _impact_lookup(state)

    def sort_key(upgrade: UpgradeSelection):
        severities = [severity_map.get(cve, "UNKNOWN") for cve in upgrade.fixes_cves]
        weight = max({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}.get(sev, 0) for sev in severities) if severities else 0
        report = _report_for_selection(state, upgrade, lookup)
        breakage = float(report.breakage_score) if report is not None else 1.0
        return (-weight, _delta_rank(_delta_kind(upgrade.from_version, upgrade.to_version)), breakage, _norm(upgrade.package))

    return sorted(items, key=sort_key)


def _colorize(text: str, color: str, *, use_color: bool) -> str:
    if not use_color or os.environ.get("NO_COLOR"):
        return text
    return f"{color}{text}{_RESET}"


def _table_rows(state: EditorState, upgrades: list[UpgradeSelection], prefix: str) -> list[list[str]]:
    rows: list[list[str]] = []
    lookup = _impact_lookup(state)
    for idx, upgrade in enumerate(upgrades, start=1):
        report = _report_for_selection(state, upgrade, lookup)
        breakage = f"{float(report.breakage_score):.2f}" if report is not None else "?"
        rows.append(
            [
                f"{prefix}{idx}",
                upgrade.package,
                upgrade.from_version,
                upgrade.to_version,
                _delta_kind(upgrade.from_version, upgrade.to_version),
                breakage,
                ", ".join(upgrade.fixes_cves) or "-",
            ]
        )
    return rows


def _render_table(title: str, rows: list[list[str]], width: int) -> str:
    headers = ["#", "Package", "From", "To", "Delta", "Breakage", "CVEs fixed"]
    if not rows:
        return f"{title}\n  (none)\n"
    cols = list(zip(headers, *rows))
    widths = [min(max(len(str(cell)) for cell in col), max(10, width // len(headers))) for col in cols]
    header_line = "  ".join(str(headers[i]).ljust(widths[i]) for i in range(len(headers)))
    separator = "  ".join("-" * widths[i] for i in range(len(headers)))
    lines = [title, header_line, separator]
    for row in rows:
        lines.append("  ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines) + "\n"


def render_editor(state: EditorState, *, use_color: bool = True) -> str:
    width = shutil.get_terminal_size((100, 24)).columns
    exposure, breakage, confidence = recalculate_scores(state)
    selected = _selection_list(state)
    available = available_upgrades(state)
    confidence_str = confidence
    if confidence == "HIGH":
        confidence_str = _colorize(confidence, _GREEN, use_color=use_color)
    elif confidence == "MEDIUM":
        confidence_str = _colorize(confidence, _YELLOW, use_color=use_color)
    else:
        confidence_str = _colorize(confidence, _BLUE, use_color=use_color)
    breakage_str = f"{breakage:.2f}"
    if breakage > 0.35:
        breakage_str = _colorize(breakage_str, _RED, use_color=use_color)
    elif breakage <= 0.15:
        breakage_str = _colorize(breakage_str, _GREEN, use_color=use_color)

    resolved = {cve for item in selected for cve in (item.fixes_cves or [])}
    no_fix = sorted({v.cve_id for v in state.all_vulns if not getattr(v, "fixed_versions", [])})
    open_cves = sorted({v.cve_id for v in state.all_vulns} - resolved - set(no_fix))

    parts = [
        "=== Remediation Editor ===",
        (
            f"Starting from: {state.selected_path_type} "
            f"(Exposure {exposure:.2f}  Breakage {breakage_str}  Confidence {confidence_str})"
        ),
        "",
        _render_table("Selected", _table_rows(state, selected, ""), width).rstrip(),
        "",
        _render_table("Available", _table_rows(state, available, "A"), width).rstrip(),
        "",
        "Open CVEs not resolved by current selection:",
        "  " + (", ".join(open_cves) if open_cves else "(none)"),
        "",
        "No-fix CVEs:",
        "  " + (", ".join(no_fix) if no_fix else "(none)"),
        "",
        "Commands",
        "  remove N | add AN | swap N AN | version N X.Y.Z | reset | path P",
        "  preview | apply | help | quit",
    ]
    return "\n".join(parts)


def _preview_diff(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None,
) -> str:
    selected = _selection_list(state)
    result = apply_remediation(
        adapter,
        manifest,
        selected,
        environment_root,
        dry_run_only=True,
    )
    if not result.success:
        return f"Preview failed: {result.error}"
    snap = snapshot(manifest, environment_root)
    try:
        adapter.write_manifest(manifest, selected, snap.files[manifest.path])
        preview_content = manifest.path.read_text(encoding="utf-8")
    finally:
        restore(snap)
    diff = difflib.unified_diff(
        snap.files[manifest.path].splitlines(),
        preview_content.splitlines(),
        fromfile=str(manifest.path),
        tofile=f"{manifest.path} (preview)",
        lineterm="",
    )
    rendered = "\n".join(diff)
    return rendered or "(no manifest changes)"


def _success_message(
    state: EditorState,
    manifest: ManifestInfo,
    result: ApplyResult,
) -> str:
    before_exposure = next(
        (path.exposure_score for path in state.all_paths if path.path_type == state.selected_path_type),
        None,
    )
    after_exposure, _breakage, _confidence = recalculate_scores(state)
    lines = [
        f"Applied {len(result.upgrades_applied)} upgrade(s) to {manifest.path}:"
    ]
    for upgrade in result.upgrades_applied:
        fixes = f" (fixes {', '.join(upgrade.fixes_cves)})" if upgrade.fixes_cves else ""
        lines.append(
            f"  ↑ {upgrade.package:<14} {upgrade.from_version} → {upgrade.to_version}{fixes}"
        )
    if manifest.has_lockfile and manifest.lockfile_path is not None:
        lines.append(f"Lockfile regenerated: {manifest.lockfile_path.name}")
    if before_exposure is not None:
        lines.append(f"Exposure reduced: {before_exposure:.2f} → {after_exposure:.2f}")
    resolved = {cve for upgrade in result.upgrades_applied for cve in upgrade.fixes_cves}
    no_fix = {v.cve_id for v in state.all_vulns if not getattr(v, "fixed_versions", [])}
    remaining = sorted({v.cve_id for v in state.all_vulns} - resolved - no_fix)
    if remaining:
        lines.append(f"Remaining open: {', '.join(remaining)}")
    lines.append("")
    lines.append("Run your test suite to verify the upgrades do not break your application.")
    return "\n".join(lines)


def execute_command(
    command: str,
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None = None,
) -> tuple[str, EditorResult | None]:
    text = command.strip()
    if not text or text in {"quit", "q"}:
        return "", EditorResult("quit", _selection_list(state), None)
    if text == "help":
        return render_editor(state, use_color=not os.environ.get("NO_COLOR")), None
    if text == "reset":
        state.selection = _base_selection_for_path(state, state.selected_path_type)
        return "Selection reset.", None
    if text.startswith("path "):
        path_type = text.split(None, 1)[1].strip()
        if path_type not in {path.path_type for path in state.all_paths}:
            return f"Unknown path type: {path_type}", None
        state.selected_path_type = path_type
        state.selection = _base_selection_for_path(state, path_type)
        return f"Switched to {path_type}.", None
    if text == "preview":
        return _preview_diff(state, adapter, manifest, environment_root), None
    if text == "apply":
        result = apply_remediation(
            adapter,
            manifest,
            _selection_list(state),
            environment_root,
        )
        if result.success:
            return _success_message(state, manifest, result), EditorResult(
                "applied",
                _selection_list(state),
                result,
            )
        return f"Apply failed: {result.error}", None

    selected = _selection_list(state)
    available = available_upgrades(state)
    parts = text.split()
    verb = parts[0]
    proposed = dict(state.selection)

    def selected_by_index(value: str) -> UpgradeSelection | None:
        if not value.isdigit():
            return None
        idx = int(value) - 1
        return selected[idx] if 0 <= idx < len(selected) else None

    def available_by_token(value: str) -> UpgradeSelection | None:
        if not value.startswith("A") or not value[1:].isdigit():
            return None
        idx = int(value[1:]) - 1
        return available[idx] if 0 <= idx < len(available) else None

    if verb == "remove" and len(parts) == 2:
        item = selected_by_index(parts[1])
        if item is None:
            return "Unknown selected upgrade.", None
        proposed.pop(_norm(item.package), None)
    elif verb == "add" and len(parts) == 2:
        item = available_by_token(parts[1])
        if item is None:
            return "Unknown available upgrade.", None
        proposed[_norm(item.package)] = item
    elif verb == "swap" and len(parts) == 3:
        current = selected_by_index(parts[1])
        new_item = available_by_token(parts[2])
        if current is None or new_item is None:
            return "Unknown swap target.", None
        proposed.pop(_norm(current.package), None)
        proposed[_norm(new_item.package)] = new_item
    elif verb == "version" and len(parts) == 3:
        current = selected_by_index(parts[1])
        if current is None:
            return "Unknown selected upgrade.", None
        replacement = UpgradeSelection(
            package=current.package,
            from_version=current.from_version,
            to_version=parts[2],
            fixes_cves=list(current.fixes_cves),
        )
        proposed[_norm(current.package)] = replacement
    else:
        return "Unknown command.", None

    conflicts = check_constraints(state, proposed)
    if conflicts:
        return "\n".join(conflicts), None

    state.selection = proposed
    if verb == "version":
        current = proposed[_norm(current.package)]  # type: ignore[name-defined]
        if _report_for_selection(state, current) is None:
            return (
                f"Breakage: unknown (no impact report cached for {current.to_version}; "
                "run with --impact-analysis to assess)",
                None,
            )
    return "Selection updated.", None


def run_editor(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None = None,
) -> EditorResult:
    if not sys.stdin.isatty():
        return EditorResult(
            action="skipped",
            selection=_selection_list(state),
            apply_result=None,
        )

    while True:
        print(render_editor(state))
        try:
            command = input("> ")
        except EOFError:
            return EditorResult("quit", _selection_list(state), None)
        message, result = execute_command(
            command,
            state,
            adapter,
            manifest,
            environment_root,
        )
        if message:
            print(message)
        if result is not None:
            return result


__all__ = [
    "EditorResult",
    "EditorState",
    "available_upgrades",
    "check_constraints",
    "execute_command",
    "recalculate_scores",
    "render_editor",
    "run_editor",
]
