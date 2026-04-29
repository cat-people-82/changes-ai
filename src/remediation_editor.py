"""Menuconfig-style remediation editor built on prompt_toolkit.

Three layers, each independently testable:

1. State layer  — pure data; no TUI imports. Fully unit-testable.
2. Application layer — apply/preview helpers; also no TUI imports.
3. TUI layer    — prompt_toolkit Application, layout, key bindings.
   Imported lazily inside run_editor() so headless CI pays no import cost.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

from src.apply import ApplyResult, UpgradeSelection, apply_remediation
from src.ecosystem.base import EcosystemAdapter, ManifestInfo
from src.remediation import (
    _build_planning_context,
    _compute_exposure_score,
    _confidence_min,
    _delta_rank,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def _semver_delta(from_version: str, to_version: str) -> str:
    def _parts(v: str) -> tuple[int, int, int]:
        nums: list[int] = []
        for part in v.split(".", 2):
            digits = "".join(ch for ch in part if ch.isdigit())
            nums.append(int(digits) if digits else 0)
        while len(nums) < 3:
            nums.append(0)
        return (nums[0], nums[1], nums[2])

    left, right = _parts(from_version), _parts(to_version)
    if left[0] != right[0]:
        return "major"
    if left[1] != right[1]:
        return "minor"
    if left[2] != right[2]:
        return "patch"
    return "patch"


# ---------------------------------------------------------------------------
# State layer
# ---------------------------------------------------------------------------

@dataclass
class PathTab:
    """One remediation path rendered as a checkbox list."""
    path_type: str
    upgrades: list[UpgradeSelection]
    selected: set[str]          # normalised package names currently checked


@dataclass
class EditorState:
    tabs: list[PathTab]
    active_tab_index: int
    cursor_index: int
    all_impact_reports: list
    all_vulns: list
    context: dict
    last_constraint_messages: list[str] = field(default_factory=list)


@dataclass
class EditorResult:
    action: str                 # "applied" | "preview" | "quit" | "skipped"
    selection: list[UpgradeSelection]
    apply_result: ApplyResult | None


def build_editor_state(
    remediation_paths: list,
    impact_reports: list,
    vulns: list,
) -> EditorState:
    """Build initial state from planner output.

    Each tab starts with all of its path's upgrades pre-selected.
    """
    tabs = []
    for path in remediation_paths:
        upgrades = [
            UpgradeSelection(
                package=u.package,
                from_version=u.from_version,
                to_version=u.to_version,
                fixes_cves=list(u.fixes_cves),
            )
            for u in path.upgrades
        ]
        selected = {_norm(u.package) for u in upgrades}
        tabs.append(PathTab(path_type=path.path_type, upgrades=upgrades, selected=selected))

    active = next(
        (i for i, t in enumerate(tabs) if t.path_type == "balanced"),
        0,
    )
    return EditorState(
        tabs=tabs,
        active_tab_index=active,
        cursor_index=0,
        all_impact_reports=impact_reports,
        all_vulns=vulns,
        context=_build_planning_context(vulns, impact_reports),
    )


# ---------------------------------------------------------------------------
# Score recalculation
# ---------------------------------------------------------------------------

def _impact_lookup(state: EditorState) -> dict[tuple[str, str, str], object]:
    return {
        (_norm(r.package), r.installed_version, r.candidate_version): r
        for r in state.all_impact_reports
    }


def recalculate_scores(state: EditorState) -> tuple[float, float, str]:
    """Return (exposure, breakage, confidence) for the active tab's selection."""
    active = state.tabs[state.active_tab_index]
    chosen = [u for u in active.upgrades if _norm(u.package) in active.selected]

    resolved = sorted({cve for u in chosen for cve in (u.fixes_cves or [])})
    no_fix = sorted({v.cve_id for v in state.all_vulns if not getattr(v, "fixed_versions", [])})
    all_cves = set(state.context.get("all_cves") or {v.cve_id for v in state.all_vulns})
    unresolved = sorted(all_cves - set(resolved) - set(no_fix))
    severity_map = state.context.get("severity_map") or {v.cve_id: v.severity for v in state.all_vulns}
    total_weight = state.context.get("total_weight")
    if total_weight is None:
        total_weight = _build_planning_context(state.all_vulns, state.all_impact_reports)["total_weight"]

    lookup = _impact_lookup(state)
    breakage_scores: list[float] = []
    confidence_labels: list[str] = []
    for u in chosen:
        report = lookup.get((_norm(u.package), u.from_version, u.to_version))
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


# ---------------------------------------------------------------------------
# Constraint check
# ---------------------------------------------------------------------------

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
    return (values[0], values[1], values[2])


def _version_satisfies(candidate: str, requirement: str) -> bool:
    candidate_triplet = _parse_version_triplet(candidate)
    if candidate_triplet is None:
        return True
    for raw_part in requirement.replace(",", " ").split():
        part = raw_part.strip()
        if not part or part == "*":
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
                if candidate_triplet >= (lower[0], lower[1] + 1, 0):
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
                if candidate_triplet >= (lower[0], lower[1] + 1, 0):
                    return False
        else:
            exact = _parse_version_triplet(part)
            if exact is not None and candidate_triplet != exact:
                return False
    return True


def check_constraints(
    state: EditorState,
    proposed_selection: set[str],   # normalised package names
) -> list[str]:
    """Return human-readable conflict messages (empty = valid)."""
    messages: list[str] = []
    active = state.tabs[state.active_tab_index]
    upgrade_map = {_norm(u.package): u for u in active.upgrades if _norm(u.package) in proposed_selection}
    reports = state.context.get("reports") or {}

    for norm_name, upgrade in upgrade_map.items():
        key = (_norm(upgrade.package), upgrade.from_version, upgrade.to_version)
        report_entry = reports.get(key)
        if report_entry is None:
            continue
        report_obj = report_entry.get("report") if isinstance(report_entry, dict) else report_entry
        dependency_constraints: dict = {}
        if isinstance(report_entry, dict):
            dependency_constraints = (
                report_entry.get("dependency_constraints")
                or report_entry.get("dependencies")
                or {}
            )
        if not dependency_constraints and report_obj is not None:
            dependency_constraints = (
                getattr(report_obj, "dependency_constraints", None)
                or getattr(report_obj, "dependencies", None)
                or {}
            )
        for dep_name, requirement in dependency_constraints.items():
            if not requirement:
                continue
            dep_norm = _norm(dep_name)
            dep_upgrade = upgrade_map.get(dep_norm)
            if dep_upgrade is None:
                if dep_norm in proposed_selection:
                    continue  # in selection but version unknown — skip
                messages.append(
                    f"{upgrade.package} {upgrade.to_version} requires "
                    f"{dep_name}{requirement} but {dep_name} is not in this selection"
                )
            elif not _version_satisfies(dep_upgrade.to_version, str(requirement)):
                messages.append(
                    f"{upgrade.package} {upgrade.to_version} requires "
                    f"{dep_name}{requirement} but {dep_name} is pinned at "
                    f"{dep_upgrade.to_version} in this selection"
                )
    return messages


# ---------------------------------------------------------------------------
# Toggle, cursor, tab
# ---------------------------------------------------------------------------

def toggle_current(state: EditorState) -> list[str]:
    """Toggle the package under the cursor. Returns any constraint warnings."""
    active = state.tabs[state.active_tab_index]
    if not active.upgrades:
        return []
    pkg = _norm(active.upgrades[state.cursor_index].package)
    if pkg in active.selected:
        active.selected.discard(pkg)
    else:
        active.selected.add(pkg)
    state.last_constraint_messages = check_constraints(state, active.selected)
    return state.last_constraint_messages


def switch_tab(state: EditorState, direction: int) -> None:
    """Move active tab by direction (+1 or -1). Wraps."""
    state.active_tab_index = (state.active_tab_index + direction) % len(state.tabs)
    state.cursor_index = 0


def move_cursor(state: EditorState, direction: int) -> None:
    """Move cursor up/down within the active tab. Clamps."""
    active = state.tabs[state.active_tab_index]
    n = len(active.upgrades)
    if n == 0:
        state.cursor_index = 0
    else:
        state.cursor_index = max(0, min(n - 1, state.cursor_index + direction))


def reset_active_tab(state: EditorState) -> None:
    """Restore the active tab's selection to all-checked."""
    active = state.tabs[state.active_tab_index]
    active.selected = {_norm(u.package) for u in active.upgrades}
    state.last_constraint_messages = []


# ---------------------------------------------------------------------------
# Apply / preview integration
# ---------------------------------------------------------------------------

def collect_selected_upgrades(state: EditorState) -> list[UpgradeSelection]:
    """Return the active tab's selected upgrades in display order."""
    active = state.tabs[state.active_tab_index]
    return [u for u in active.upgrades if _norm(u.package) in active.selected]


def run_preview(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None,
) -> ApplyResult:
    return apply_remediation(
        adapter, manifest, collect_selected_upgrades(state),
        environment_root, dry_run_only=True,
    )


def run_apply(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None,
) -> ApplyResult:
    return apply_remediation(
        adapter, manifest, collect_selected_upgrades(state),
        environment_root, dry_run_only=False,
    )


# ---------------------------------------------------------------------------
# Help text (contextual details pane)
# ---------------------------------------------------------------------------

def help_text_for_cursor(state: EditorState) -> str:
    """Return the contextual help shown in the details pane for the cursor row."""
    active = state.tabs[state.active_tab_index]
    if not active.upgrades:
        return "(no upgrades)"
    upgrade = active.upgrades[state.cursor_index]
    lookup = _impact_lookup(state)
    report = lookup.get((_norm(upgrade.package), upgrade.from_version, upgrade.to_version))

    delta = _semver_delta(upgrade.from_version, upgrade.to_version)
    lines = [
        f"Package:  {upgrade.package}",
        f"From:     {upgrade.from_version}",
        f"To:       {upgrade.to_version}",
        f"Delta:    {delta}",
    ]
    if report is not None:
        lines.append(f"Breakage: {float(report.breakage_score):.2f} ({report.probable_breakage})")
        lines.append(f"Conf:     {report.confidence}")
        if getattr(report, "confidence_reason", ""):
            lines.append(f"Reason:   {report.confidence_reason}")
    if upgrade.fixes_cves:
        lines.append("")
        lines.append("Fixes:")
        severity_map = state.context.get("severity_map") or {}
        for cve in upgrade.fixes_cves:
            sev = severity_map.get(cve, "")
            suffix = f" ({sev})" if sev else ""
            lines.append(f"  - {cve}{suffix}")
    if report is not None and getattr(report, "evidence", ""):
        lines.append("")
        lines.append("Evidence:")
        for sentence in report.evidence.strip().split(". "):
            if sentence:
                lines.append(f"  {sentence.rstrip('.')}.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# TUI renderers (formatted text — no Application import needed)
# ---------------------------------------------------------------------------

EDITOR_STYLE = {
    "tab":                   "fg:#888888",
    "tab.active":            "fg:#ffffff bold",
    "row.cursor":            "reverse",
    "row.severity.critical": "fg:#991B1B bold",
    "row.severity.high":     "fg:#9A3412 bold",
    "row.severity.medium":   "fg:#92400E",
    "row.severity.low":      "fg:#1E40AF",
    "scores.label":          "fg:#6b7280",
    "score.good":            "fg:#047857",
    "score.warn":            "fg:#9A3412",
    "score.bad":             "fg:#991B1B",
    "confidence.high":       "fg:#047857",
    "confidence.medium":     "fg:#9A3412",
    "confidence.low":        "fg:#991B1B",
    "warning":               "fg:#991B1B bold",
}


def _row_style(upgrade: UpgradeSelection, all_vulns: list, *, is_cursor: bool) -> str:
    if is_cursor:
        return "class:row.cursor"
    severity_map = {v.cve_id: v.severity for v in all_vulns}
    severities = [severity_map.get(cve, "UNKNOWN") for cve in (upgrade.fixes_cves or [])]
    worst = max(
        ({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0) for s in severities),
        default=0,
    )
    return {4: "class:row.severity.critical", 3: "class:row.severity.high",
            2: "class:row.severity.medium", 1: "class:row.severity.low"}.get(worst, "")


def _score_style(value: float, *, kind: str) -> str:
    if kind == "exposure":
        if value <= 0.2:
            return "class:score.good"
        if value <= 0.5:
            return "class:score.warn"
        return "class:score.bad"
    # breakage
    if value <= 0.15:
        return "class:score.good"
    if value <= 0.35:
        return "class:score.warn"
    return "class:score.bad"


def _confidence_style(conf: str) -> str:
    return {"HIGH": "class:confidence.high", "MEDIUM": "class:confidence.medium"}.get(
        conf, "class:confidence.low"
    )


def _render_tab_bar(state: EditorState) -> list[tuple[str, str]]:
    parts = []
    for i, tab in enumerate(state.tabs):
        active = (i == state.active_tab_index)
        label = tab.path_type.replace("_", " ").title()
        marker = "[ "
        end = " ]"
        style = "class:tab.active" if active else "class:tab"
        parts.append((style, f"{marker}{label}{end}"))
        parts.append(("", "  "))
    return parts


def _render_selection(state: EditorState) -> list[tuple[str, str]]:
    active = state.tabs[state.active_tab_index]
    lines: list[tuple[str, str]] = []
    for i, upgrade in enumerate(active.upgrades):
        is_cursor = (i == state.cursor_index)
        is_checked = _norm(upgrade.package) in active.selected
        marker = "[x]" if is_checked else "[ ]"
        delta = _semver_delta(upgrade.from_version, upgrade.to_version)
        line = f"{marker}  {upgrade.package:24}  {upgrade.from_version} → {upgrade.to_version}  ({delta})"
        style = _row_style(upgrade, state.all_vulns, is_cursor=is_cursor)
        lines.append((style, line + "\n"))
    return lines


def _render_scores_bar(state: EditorState) -> list[tuple[str, str]]:
    exp, brk, conf = recalculate_scores(state)
    parts: list[tuple[str, str]] = [
        ("class:scores.label", "Exposure "),
        (_score_style(exp, kind="exposure"), f"{exp:.2f}"),
        ("", "  "),
        ("class:scores.label", "Breakage "),
        (_score_style(brk, kind="breakage"), f"{brk:.2f}"),
        ("", "  "),
        ("class:scores.label", "Confidence "),
        (_confidence_style(conf), conf),
    ]
    if state.last_constraint_messages:
        parts.append(("", "\n"))
        parts.append(("class:warning", "⚠  " + state.last_constraint_messages[0]))
    return parts


def _render_keybindings_bar() -> list[tuple[str, str]]:
    return [("", "↑↓ move  space toggle  tab/⇧tab path  p preview  a apply  r reset  q quit")]


# ---------------------------------------------------------------------------
# TUI layer (prompt_toolkit — imported lazily)
# ---------------------------------------------------------------------------

def _run_tui(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None,
) -> EditorResult:
    from prompt_toolkit import Application
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import FloatContainer, HSplit, VSplit, Float
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.styles import Style
    from prompt_toolkit.widgets import Frame

    nonlocal_result: dict = {"value": None}
    modal_text: dict = {"content": ""}
    show_modal: dict = {"visible": False}

    # --- renderers ---------------------------------------------------------

    def tab_bar_text():
        return _render_tab_bar(state)

    def selection_text():
        return _render_selection(state)

    def details_text():
        return help_text_for_cursor(state)

    def scores_text():
        return _render_scores_bar(state)

    # --- layout ------------------------------------------------------------

    tab_bar = Frame(
        body=__import__("prompt_toolkit.layout.containers", fromlist=["Window"]).Window(
            content=FormattedTextControl(text=tab_bar_text),
            height=1,
        ),
    )

    selection_pane = Frame(
        body=__import__("prompt_toolkit.layout.containers", fromlist=["Window"]).Window(
            content=FormattedTextControl(text=selection_text),
            wrap_lines=False,
        ),
        title="Selection",
    )

    details_pane = Frame(
        body=__import__("prompt_toolkit.layout.containers", fromlist=["Window"]).Window(
            content=FormattedTextControl(text=details_text),
            wrap_lines=True,
        ),
        title="Details",
    )

    scores_bar = __import__("prompt_toolkit.layout.containers", fromlist=["Window"]).Window(
        content=FormattedTextControl(text=scores_text),
        height=2,
    )

    keys_bar = __import__("prompt_toolkit.layout.containers", fromlist=["Window"]).Window(
        content=FormattedTextControl(text=_render_keybindings_bar()),
        height=1,
    )

    modal_window = Frame(
        body=__import__("prompt_toolkit.layout.containers", fromlist=["Window"]).Window(
            content=FormattedTextControl(text=lambda: modal_text["content"]),
            wrap_lines=True,
        ),
        title="Preview",
    )

    root = FloatContainer(
        content=HSplit([tab_bar, VSplit([selection_pane, details_pane]), scores_bar, keys_bar]),
        floats=[
            Float(
                content=modal_window,
                transparent=False,
            )
        ],
    )

    layout = Layout(root)

    # --- key bindings ------------------------------------------------------

    kb = KeyBindings()

    @kb.add("up")
    def _(event):
        move_cursor(state, -1)
        event.app.invalidate()

    @kb.add("down")
    def _(event):
        move_cursor(state, +1)
        event.app.invalidate()

    @kb.add("space")
    def _(event):
        toggle_current(state)
        event.app.invalidate()

    @kb.add("tab")
    def _(event):
        switch_tab(state, +1)
        event.app.invalidate()

    @kb.add("s-tab")
    def _(event):
        switch_tab(state, -1)
        event.app.invalidate()

    @kb.add("r")
    def _(event):
        reset_active_tab(state)
        event.app.invalidate()

    @kb.add("p")
    def _(event):
        result = run_preview(state, adapter, manifest, environment_root)
        if result.success:
            # Produce a diff by temporarily writing the manifest and reading it back
            from src.apply import snapshot as _snapshot, restore as _restore
            snap = _snapshot(manifest, environment_root)
            try:
                adapter.write_manifest(manifest, collect_selected_upgrades(state), snap.files[manifest.path])
                new_content = manifest.path.read_text(encoding="utf-8")
            finally:
                _restore(snap)
            diff_lines = difflib.unified_diff(
                snap.files[manifest.path].splitlines(),
                new_content.splitlines(),
                fromfile=str(manifest.path),
                tofile=f"{manifest.path} (preview)",
                lineterm="",
            )
            modal_text["content"] = "\n".join(diff_lines) or "(no manifest changes)"
        else:
            modal_text["content"] = f"Preview failed: {result.error}"
        show_modal["visible"] = True
        event.app.invalidate()

    @kb.add("a")
    def _(event):
        result = run_apply(state, adapter, manifest, environment_root)
        nonlocal_result["value"] = EditorResult(
            action="applied" if result.success else "quit",
            selection=collect_selected_upgrades(state),
            apply_result=result,
        )
        event.app.exit()

    @kb.add("q")
    @kb.add("c-c")
    def _(event):
        nonlocal_result["value"] = EditorResult(
            action="quit",
            selection=collect_selected_upgrades(state),
            apply_result=None,
        )
        event.app.exit()

    @kb.add("escape")
    @kb.add("enter")
    def _(event):
        if show_modal["visible"]:
            show_modal["visible"] = False
            modal_text["content"] = ""
            event.app.invalidate()

    # Hide the float when modal is not visible
    _float = root.floats[0]

    def _before_render(app):
        _float.hide = not show_modal["visible"]

    app = Application(
        layout=layout,
        key_bindings=kb,
        style=Style.from_dict(EDITOR_STYLE),
        full_screen=True,
        before_render=_before_render,
    )
    app.run()

    if nonlocal_result["value"] is None:
        return EditorResult("quit", collect_selected_upgrades(state), None)
    return nonlocal_result["value"]


def run_editor(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None = None,
) -> EditorResult:
    """Launch the menuconfig-style TUI. Skips when stdin is not a TTY."""
    import sys
    if not sys.stdin.isatty():
        return EditorResult(
            action="skipped",
            selection=collect_selected_upgrades(state),
            apply_result=None,
        )
    return _run_tui(state, adapter, manifest, environment_root)


__all__ = [
    "EditorResult",
    "EditorState",
    "PathTab",
    "build_editor_state",
    "check_constraints",
    "collect_selected_upgrades",
    "help_text_for_cursor",
    "move_cursor",
    "recalculate_scores",
    "reset_active_tab",
    "run_apply",
    "run_editor",
    "run_preview",
    "switch_tab",
    "toggle_current",
    "_render_tab_bar",
    "_render_selection",
    "_render_scores_bar",
]
