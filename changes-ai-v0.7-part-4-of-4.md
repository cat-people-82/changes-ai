# Changes AI v0.7 — Part 4 of 4

## Remediation Editor & CLI Wiring

This is the final part of the v0.7 release. **Do not start this part
until Parts 1, 2, and 3 are complete and the test suite passes.**

- Part 1: Ecosystem adapter protocol + Python migration. ✅ done.
- Part 2: OSV per-ecosystem routing + apply pipeline for Python. ✅ done.
- Part 3: NPM adapter + JS/TS usage analyser. ✅ done.
- **Part 4 (this document):** Interactive editor + CLI wiring for
  `--apply` / `--auto-apply` / `--ecosystem`.

---

## Goal of Part 4

Expose Parts 2 and 3 to users:

- Interactive editor where the user reviews, customises, and applies a
  remediation path.
- Non-interactive `--auto-apply` for CI use, with `--max-breakage-score`
  as a safety guard.
- `--ecosystem` flag for polyglot repositories.
- README + CHANGELOG documentation for everything shipped in v0.7.

After this part, v0.7 is feature-complete and ready to release.

---

## Context

Read these files before writing any plan or code:

- `src/changes_ai.py` — `_print_remediation_plan` (line ~993), the
  argument parser (line ~1708), `main()` tail (line ~2374). The editor
  integration lands immediately after the plan is printed.
- `src/remediation.py` — `RemediationPath`, `RemediationUpgrade`,
  `_compute_exposure_score`, `_SEVERITY_WEIGHTS`, `_make_path`,
  `_build_planning_context`, `_confidence_min`. The editor reuses these
  directly — do not reimplement scoring.
- `src/apply.py` — `apply_remediation`, `UpgradeSelection`, `ApplyResult`.
- `src/ecosystem/base.py` — `EcosystemAdapter`, `ManifestInfo`.
- `tests/test_smoke.py` — extend; do not duplicate existing fixtures.
- `README.md` and `CHANGELOG.md`.

---

## Constraints

- New module: `src/remediation_editor.py`. New tests in
  `tests/test_smoke.py`.
- All new tests must be deterministic. No real stdin reads — use
  `monkeypatch` against `sys.stdin` and `sys.stdin.isatty`.
- `rich` and `tabulate` are not available. Stdlib only (`textwrap`,
  `shutil`, `sys`, `os`, `difflib`).
- The editor loop must be skipped entirely when stdin is not a TTY.
  Non-interactive runs use `--auto-apply` instead.
- `--auto-apply` must name an explicit path type. It must not be
  silently triggered by `--plan`. A `--max-breakage-score` guard is
  required for safety.
- `--apply` and `--auto-apply` both require `--source` (cannot modify a
  remote `--url` checkout). Print a warning and skip otherwise.
- All changes must pass `pytest tests/` before the release is marked
  done.

---

## Task 4.1 — Remediation editor

**File:** `src/remediation_editor.py` (new)

The editor is ecosystem-agnostic. It operates on `RemediationPath`
objects and `UpgradeSelection` instances. Adapter is needed only for
the apply call.

### 4.1a — State

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

from src.remediation import (
    _compute_exposure_score,
    _confidence_min,
    _build_planning_context,
)
from src.apply import apply_remediation, UpgradeSelection, ApplyResult
from src.ecosystem.base import EcosystemAdapter, ManifestInfo


@dataclass
class EditorState:
    all_paths: list                # list[RemediationPath]
    all_impact_reports: list       # list[ImpactReport]
    all_vulns: list                # list[VulnerabilityRecord]
    selected_path_type: str        # base path type for "reset"
    selection: dict[str, UpgradeSelection]  # keyed by normalised package name
    context: dict                  # _build_planning_context output


@dataclass
class EditorResult:
    action: str                    # "applied" | "preview" | "quit" | "skipped"
    selection: list[UpgradeSelection]
    apply_result: ApplyResult | None
```

State invariant: `selection` is always keyed by
`package.lower().replace("_", "-")`. All operations that read from
`selection` normalise the key before lookup.

### 4.1b — Score recalculation

```python
def recalculate_scores(state: EditorState) -> tuple[float, float, str]:
    """Returns (exposure, breakage, confidence) for the current selection.

    Exposure: deterministic via _compute_exposure_score.
    Breakage: max breakage_score across selected packages (per impact report).
    Confidence: minimum confidence across selected packages.
    """
```

Build a synthetic `RemediationPath` from the current selection. Pass to
`_compute_exposure_score` for the exposure value. Look up each
selection's package in `state.all_impact_reports` to find its
breakage_score and confidence. Apply `_confidence_min` over the list.
Do not reimplement the scoring math.

### 4.1c — Constraint check (fast local)

```python
def check_constraints(
    state: EditorState,
    proposed_selection: dict[str, UpgradeSelection],
) -> list[str]:
    """Return human-readable conflict messages (empty = valid)."""
```

Walks impact-report dependency edges in `state.context["reports"]` (the
planning context from Part 1's `_build_planning_context`). For each
upgrade in `proposed_selection`, check whether any other upgrade in the
selection declares a constraint on this package's version that the
proposed `to_version` would not satisfy. Returns messages like:
`"requests 2.33.0 requires urllib3>=2.6.0 but urllib3 is pinned at 2.5.0 in this selection"`.

The dry-run validator in `apply.py` is the correctness gate. This is
just the fast first pass.

### 4.1d — Available upgrades

```python
def available_upgrades(state: EditorState) -> list[UpgradeSelection]:
    """Upgrade candidates from other paths not in the current selection.

    Sorted by:
      1. Severity of fixed CVEs (highest first).
      2. Delta rank (patch < minor < major).
      3. Breakage score ascending.
    """
```

Walk all paths in `state.all_paths` for paths != `selected_path_type`.
Collect their upgrades. Filter to packages not already in
`state.selection`. Deduplicate by `(package, to_version)`.

### 4.1e — Render

```python
def render_editor(state: EditorState, *, use_color: bool = True) -> str:
    """Return the full editor display as a string.

    Returned (not printed) so tests can assert on its contents.
    """
```

Layout sections in order:

1. Title bar: `"=== Remediation Editor ==="` plus
   `"Starting from: <path_type> (Exposure X.XX  Breakage X.XX  Confidence Y)"`.
2. Selected upgrades table — numbered `1..N`. Columns: number,
   package, from, to, delta (`patch`/`minor`/`major`), breakage,
   CVEs fixed.
3. Available upgrades table — numbered `A1..AN`. Same columns.
4. Open CVEs not resolved by any selected upgrade.
5. No-fix CVEs.
6. Command reference (one line per command).

Adaptive column widths via `shutil.get_terminal_size()`. ANSI codes
match the existing palette in `_print_remediation_plan`:

- GREEN (`\033[0;32m`) for HIGH confidence, low breakage.
- YELLOW (`\033[0;33m`) for MEDIUM confidence.
- BLUE (`\033[0;34m`) for LOW breakage.
- RED (`\033[0;31m`) for HIGH breakage (> 0.35).

When `use_color=False` or the `NO_COLOR` env var is set, emit no ANSI
codes. The function returns a single string — print it from the loop,
not from inside the function. This makes Test 4.1g.5 trivial (assert
substrings in the returned string).

### 4.1f — Command loop

```python
def run_editor(
    state: EditorState,
    adapter: EcosystemAdapter,
    manifest: ManifestInfo,
    environment_root: Path | None = None,
) -> EditorResult:
    """Run the interactive loop. Skips with action='skipped' when stdin is not a TTY."""
    import sys
    if not sys.stdin.isatty():
        return EditorResult(action="skipped", selection=list(state.selection.values()),
                            apply_result=None)
    # ... main loop ...
```

Commands:

| Command | Behaviour |
|---|---|
| `remove N` | Remove selected upgrade N. Run `check_constraints` against the proposed (post-remove) selection. If conflicts, print them and abort the change. |
| `add AN` | Add available upgrade AN. Run `check_constraints`; print conflicts and abort if any. |
| `swap N AN` | Atomic remove-then-add. |
| `version N X.Y.Z` | Replace selected upgrade N's `to_version`. If no impact report cached for that version, warn `"Breakage: unknown (no impact report cached for X.Y.Z); run with --impact-analysis to assess"`. |
| `reset` | Restore `selection` to the original state of `selected_path_type`. |
| `path P` | Switch base path type (`min` / `balanced` / `max`). Resets `selection` to that path's upgrades. |
| `preview` | `apply_remediation(adapter, manifest, list(state.selection.values()), environment_root, dry_run_only=True)`. Print a unified diff via `difflib.unified_diff` between the current manifest content and the would-be content (use the snapshot returned by `apply.snapshot`). |
| `apply` | `apply_remediation(...)` (not dry-run). On success, print confirmation and return `EditorResult(action="applied", ...)`. On failure, print the error and remain in the loop. |
| `help` | Reprint the command reference. |
| `quit` / `q` / empty Enter | Return `EditorResult(action="quit", ...)`. |

After successful `apply`, print:

```
Applied 3 upgrade(s) to <manifest_path>:
  ↑ urllib3       2.5.0 → 2.6.3   (fixes GHSA-..., GHSA-..., GHSA-...)
  ↑ requests      2.32.5 → 2.33.0 (fixes GHSA-...)
  ↑ python-dotenv 1.2.1 → 1.2.2   (fixes GHSA-...)

Lockfile regenerated: requirements.txt.lock        ← only when has_lockfile
Exposure reduced: 0.54 → 0.16
Remaining open: GHSA-... (pip, no fix available)

Run your test suite to verify the upgrades do not break your application.
```

The "Lockfile regenerated" line is omitted if `manifest.has_lockfile is
False`. The "Remaining open" line is omitted if there are no open CVEs.

### 4.1g — Tests

All in `tests/test_smoke.py`:

- `test_editor_recalculate_matches_remediation_module` — minimal
  `EditorState` with two upgrades resolving HIGH and MEDIUM CVEs; assert
  `recalculate_scores` exposure equals the value `_compute_exposure_score`
  produces directly with the same inputs.
- `test_editor_constraint_check_flags_version_conflict` — context where
  `requests 2.33.0` declares `urllib3>=2.6.0`; selection containing
  `requests 2.33.0` + `urllib3 2.5.0`; assert non-empty messages list
  containing both `requests` and `urllib3`.
- `test_editor_skips_when_not_tty` — monkeypatch `sys.stdin.isatty` to
  return `False`; call `run_editor`; assert returns immediately with
  `action="skipped"`, no input read, no file modified.
- `test_editor_render_produces_expected_sections` — `use_color=False`;
  assert the string contains `"Selected"`, `"Available"`, `"Commands"`,
  the package name of a selected upgrade, and the CVE ID being fixed.
- `test_editor_swap_command_replaces_selection` — call the command
  parser directly with `swap 1 A1` against a known state; assert the
  selection now contains the available upgrade and not the original.
- `test_editor_reset_command_restores_initial_selection` — modify
  selection, call `reset`, assert restored.
- `test_editor_preview_does_not_modify_manifest` — `tmp_path` with a
  manifest; call `preview`; assert manifest content on disk is
  unchanged.

---

## Task 4.2 — CLI wiring

**File:** `src/changes_ai.py`

### 4.2a — New arguments

Add to the argument parser, immediately after the existing `--plan`
flag:

```python
parser.add_argument(
    "--apply",
    action="store_true",
    help=(
        "After the remediation plan is produced, open an interactive editor "
        "to review and apply a path. Requires --plan and --source. Skipped "
        "when stdin is not a TTY (use --auto-apply for non-interactive use)."
    ),
)
parser.add_argument(
    "--auto-apply",
    metavar="PATH_TYPE",
    choices=["minimum_breakage", "balanced", "maximum_coverage"],
    default=None,
    help=(
        "Non-interactively apply the named remediation path. Requires --plan "
        "and --source. Combine with --max-breakage-score to refuse "
        "application above a threshold."
    ),
)
parser.add_argument(
    "--max-breakage-score",
    type=float,
    metavar="SCORE",
    default=None,
    help=(
        "When --auto-apply is used, refuse to apply any path whose breakage "
        "score exceeds SCORE (0.0–1.0). Exit with code 3 if exceeded."
    ),
)
parser.add_argument(
    "--ecosystem",
    choices=["python", "npm"],
    default=None,
    help=(
        "Override automatic ecosystem detection. Useful for polyglot repos "
        "where both Python and NPM manifests are present."
    ),
)
```

### 4.2b — Honour `--ecosystem` override

In `main()`, replace the Part 1 `detect_adapter(source_path)` call with:

```python
from .ecosystem import detect_adapter, REGISTRY

if args.ecosystem:
    adapter = REGISTRY[args.ecosystem]
    # Verify a manifest of the chosen ecosystem actually exists
    if adapter.find_manifest(source_path) is None:
        print(
            f"Error: --ecosystem {args.ecosystem} specified but no "
            f"matching manifest found in {source_path}.",
            file=sys.stderr,
        )
        sys.exit(1)
else:
    adapter = detect_adapter(source_path)
    if adapter is None:
        print(
            f"Error: no supported ecosystem detected in {source_path}. "
            f"Supported: {', '.join(REGISTRY)}.",
            file=sys.stderr,
        )
        sys.exit(1)
```

### 4.2c — Wire apply step

Immediately after `_print_remediation_plan(remediation_paths,
all_vulns)` (line ~2374), add:

```python
if (args.apply or args.auto_apply) and remediation_paths:
    from .remediation_editor import run_editor, EditorState
    from .apply import apply_remediation, UpgradeSelection
    from src.remediation import _build_planning_context

    if not args.source:
        print(
            "Warning: --apply / --auto-apply requires --source (cannot "
            "modify a remote --url checkout). Skipping.",
            file=sys.stderr,
        )
    else:
        environment_root = None
        # For Python, this is the venv path; for NPM, the project root.
        # Adapters can override this via a future protocol method;
        # for v0.7, derive it from find_venv (Python) or source_path (NPM).
        if adapter.name == "python":
            try:
                environment_root = find_venv(args.source)
            except FileNotFoundError:
                environment_root = None
        else:
            environment_root = source_path

        if args.auto_apply:
            target = next(
                (p for p in remediation_paths if p.path_type == args.auto_apply),
                None,
            )
            if target is None:
                print(
                    f"Error: no remediation path of type "
                    f"'{args.auto_apply}' was generated.",
                    file=sys.stderr,
                )
                cache.finish_run(run_id, status="failed")
                cache.close()
                sys.exit(1)

            if (args.max_breakage_score is not None
                    and target.breakage_score > args.max_breakage_score):
                print(
                    f"Error: path '{args.auto_apply}' has breakage score "
                    f"{target.breakage_score:.2f}, which exceeds "
                    f"--max-breakage-score {args.max_breakage_score:.2f}. "
                    "Not applying.",
                    file=sys.stderr,
                )
                cache.finish_run(run_id, status="completed")
                cache.close()
                sys.exit(3)

            upgrades = [
                UpgradeSelection(
                    package=u.package,
                    from_version=u.from_version,
                    to_version=u.to_version,
                    fixes_cves=u.fixes_cves,
                )
                for u in target.upgrades
            ]
            result = apply_remediation(
                adapter, manifest_info, upgrades, environment_root,
            )
            if not result.success:
                print(f"Error: apply failed: {result.error}", file=sys.stderr)
                cache.finish_run(run_id, status="failed")
                cache.close()
                sys.exit(1)
            print(f"Auto-applied '{args.auto_apply}' path successfully.")

        else:  # --apply (interactive)
            if not sys.stdin.isatty():
                print(
                    "Note: --apply ignored in non-interactive mode. Use "
                    "--auto-apply for CI use.",
                    file=sys.stderr,
                )
            else:
                context = _build_planning_context(all_vulns, impact_reports)
                base = next(
                    (p for p in remediation_paths if p.path_type == "balanced"),
                    remediation_paths[0],
                )
                state = EditorState(
                    all_paths=remediation_paths,
                    all_impact_reports=impact_reports,
                    all_vulns=all_vulns,
                    selected_path_type=base.path_type,
                    selection={
                        u.package.lower().replace("_", "-"): UpgradeSelection(
                            package=u.package,
                            from_version=u.from_version,
                            to_version=u.to_version,
                            fixes_cves=u.fixes_cves,
                        )
                        for u in base.upgrades
                    },
                    context=context,
                )
                run_editor(state, adapter, manifest_info, environment_root)
```

### 4.2d — Exit codes

Document and enforce these exit codes:

- `0`: success.
- `1`: tool error.
- `2`: `--fail-on` threshold exceeded (existing behaviour).
- `3`: `--auto-apply` blocked by `--max-breakage-score`.

### 4.2e — Tests

- `test_cli_apply_requires_source` — call `main()` with `--apply`
  but no `--source`; assert the warning is printed and the process
  exits 0 without crashing.
- `test_cli_auto_apply_exits_3_when_breakage_exceeds_threshold` —
  build a minimal cache fixture with a remediation path whose
  breakage_score is 0.5; run the CLI with `--auto-apply balanced
  --max-breakage-score 0.3`; assert exit code 3 and that no manifest
  file was modified.
- `test_cli_ecosystem_override_with_no_matching_manifest_exits_1` —
  `tmp_path` with only `pyproject.toml`; run with `--ecosystem npm`;
  assert exit code 1 and a clear error message.
- `test_cli_apply_in_non_tty_prints_note_and_skips` — monkeypatch
  `sys.stdin.isatty` → `False`; run with `--apply`; assert the note
  is printed and no editor loop runs.

---

## Task 4.3 — Documentation

### 4.3a — README

`README.md` — add or update these sections:

**Supported ecosystems:**

```markdown
## Supported ecosystems

| Ecosystem | Manifests                                       | Lockfiles                                         |
|-----------|-------------------------------------------------|---------------------------------------------------|
| Python    | `requirements.txt`, `pyproject.toml`,           | `uv.lock`, `poetry.lock`                          |
|           | `requirements/*.txt`, `environment.yml`         |                                                   |
| NPM       | `package.json`                                  | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`|

Ecosystem is detected automatically from the contents of the source
directory. For polyglot repositories with both `pyproject.toml` and
`package.json` at the same depth, Python wins by default. Use
`--ecosystem npm` to override.
```

**Apply examples:**

```markdown
## Applying remediations

### Interactive (recommended for local use)

    changes-ai --source . --all --apply

After the plan is printed, an interactive editor opens. Customise the
selection, preview the diff, then apply.

### Non-interactive (for CI)

    changes-ai --source . --all \
        --auto-apply balanced \
        --max-breakage-score 0.3

Applies the balanced path without prompting. Refuses to apply if the
balanced path's breakage score exceeds 0.3 (exit code 3).

### Lockfile regeneration

After writing the manifest, Changes AI regenerates the project's
lockfile by invoking the appropriate tool. The relevant tool must be
on `PATH`:

| Lockfile             | Tool             |
|----------------------|------------------|
| `uv.lock`            | `uv lock`        |
| `poetry.lock`        | `poetry lock`    |
| `package-lock.json`  | `npm install --package-lock-only` |
| `yarn.lock`          | `yarn install`   |
| `pnpm-lock.yaml`     | `pnpm install`   |

If the tool is missing, the apply step fails clearly and the manifest
is rolled back to its previous state.
```

### 4.3b — CHANGELOG

`CHANGELOG.md` — add a `[0.7.0]` section at the top:

```markdown
## [0.7.0] - <date>

### Added — Ecosystem support
- **NPM ecosystem support.** Discovers and parses `package.json`,
  `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 and berry), and
  `pnpm-lock.yaml`. Routes OSV queries via the `npm` ecosystem and
  uses the npm registry directly for currency checks (no API key
  required).
- **JS/TS usage analysis.** Tree-sitter-based AST walker collects
  symbol-level imports across `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`,
  `.cjs` files. Static imports, CommonJS requires, and dynamic
  imports with literal arguments are resolved; dynamic, re-export,
  and member-access cases are flagged as unresolved.
- **`EcosystemAdapter` protocol** in `src/ecosystem/`. Every
  ecosystem-specific operation — manifest discovery, parsing,
  currency, dependency graphs, usage analysis, manifest writes,
  lockfile regeneration, install — goes through the protocol.
  `PythonAdapter` and `NpmAdapter` are the first two implementations.

### Added — Remediation apply
- **Interactive remediation editor (`--apply`).** After the plan is
  produced, opens a loop where the user can customise the upgrade
  selection, check constraint validity in real time, preview the
  manifest diff, and apply the chosen path in one step.
- **Non-interactive apply (`--auto-apply PATH_TYPE`).** Applies a
  named remediation path without prompting. Designed for CI. Combine
  with `--max-breakage-score` to refuse application above a breakage
  threshold (exits with code 3).
- **Lockfile regeneration.** Both ecosystems regenerate their
  lockfiles after manifest writes (`uv lock` / `poetry lock` /
  `npm install --package-lock-only` /
  `yarn install --mode=update-lockfile` /
  `pnpm install --lockfile-only`). If the relevant tool is missing,
  the apply step fails clearly and rolls back.
- **`--ecosystem` flag** to override automatic ecosystem detection
  in polyglot repos.

### Changed
- OSV queries now route per-ecosystem (was hardcoded `PyPI`).
  Existing Python scans behave identically; NPM scans use
  `ecosystem: "npm"`.
- Python manifest writes for `pyproject.toml` use regex-based
  in-place rewriting to preserve formatting and comments.

### Notes
- The editor is skipped in non-interactive environments. Use
  `--auto-apply` for pipeline use.
- v0.7 includes JS/TS usage analysis but does *not* include
  reachability analysis through bundlers (webpack, esbuild, vite).
  Bundler-aware reachability is on the v0.9 roadmap.
```

---

## Definition of Done — v0.7 Release

- [ ] `pytest tests/` passes with zero failures and zero errors.
- [ ] `changes-ai --version` works from a clean `pip install -e .`.
- [ ] **Python parity:** all v0.6 tests still pass without
  modification. Python users see no behaviour change for existing
  flags.
- [ ] **NPM scan:** `changes-ai --source <npm-project> --cve-scan`
  discovers `package.json`, parses any present lockfile, queries OSV
  with `ecosystem: "npm"`, and prints findings.
- [ ] **NPM full pipeline:** `changes-ai --source <npm-project>
  --all` produces a remediation plan with NPM upgrades.
- [ ] **Apply (Python interactive):** `changes-ai --source
  <py-project> --all --apply` enters the editor when stdin is a
  TTY; applying a path writes the manifest, regenerates the lockfile
  (if `uv` or `poetry` is present), runs install, and the new
  versions are visible to a follow-up scan.
- [ ] **Apply (NPM interactive):** same workflow with a
  `package.json` project.
- [ ] **Auto-apply with breakage guard:** `--auto-apply balanced
  --max-breakage-score 0.0` exits with code 3 (any real path exceeds
  0.0).
- [ ] **Rollback works:** if `npm install` (or `pip install`) fails
  after the manifest is written, the manifest is restored on disk
  and the tool exits non-zero.
- [ ] **Polyglot detection:** running on a directory with both
  `package.json` and `pyproject.toml` warns and picks one;
  `--ecosystem` overrides cleanly.
- [ ] `CHANGELOG.md` has a `[0.7.0]` entry covering both the
  ecosystem and apply sections.
- [ ] `README.md` documents both ecosystems and the `--apply` /
  `--auto-apply` flags with examples.
