# Changes AI v0.7 — Part 3 of 4

## NPM Adapter & JS/TS Usage Analyser

This is part 3 of the v0.7 release. **Do not start this part until
Parts 1 and 2 are complete and the test suite passes.**

- Part 1: Ecosystem adapter protocol + Python migration. ✅ done.
- Part 2: OSV per-ecosystem routing + apply pipeline for Python. ✅ done.
- **Part 3 (this document):** NPM adapter (parsers, currency, graph,
  install) + JS/TS usage analyser.
- Part 4: Interactive editor + CLI wiring for `--apply` / `--auto-apply` /
  `--ecosystem`.

---

## Goal of Part 3

First non-Python ecosystem under the protocol, plus the symbol-level
usage analyser that gives NPM scans the same impact-assessment quality
Python scans get from `usage.py`.

After this part:
- `changes-ai --source <npm-project> --cve-scan` produces NPM
  vulnerability findings via OSV.
- `changes-ai --source <npm-project> --all` runs the full pipeline
  (currency, graph, usage, impact, plan) for an NPM project.
- The full apply pipeline from Part 2 works against NPM manifests.

The `--apply` / `--auto-apply` CLI flags themselves don't exist yet —
that's Part 4. NPM scans run automatically because `detect_adapter` from
Part 1 picks up the new `NpmAdapter` once it's in the registry.

---

## Context

Read these files before writing any plan or code:

- `src/ecosystem/base.py` — protocol contract.
- `src/ecosystem/python_adapter.py` — reference implementation. NPM
  adapter mirrors its structure.
- `src/usage.py` — Python AST analyser. The JS/TS analyser is the
  same shape with a different parser.
- `src/changes_ai.py` — `LibrariesIOClient` is the model for
  `NpmRegistryClient`.
- `src/apply.py` — the orchestrator already calls adapter methods;
  NPM just needs to implement them.
- `tests/test_smoke.py` — extend with NPM-specific tests.
- `pyproject.toml` — needs three new dependencies.

---

## Constraints

- New modules: `src/ecosystem/npm_adapter.py`, `src/ecosystem/js_usage.py`.
  New tests in `tests/test_smoke.py`. Test fixtures in
  `tests/fixtures/npm/`.
- All new tests must be deterministic. Mock HTTP for npm registry; mock
  subprocess for install/lockfile tests.
- `tree_sitter`, `tree-sitter-javascript`, and `tree-sitter-typescript`
  are added to `pyproject.toml` `[project.dependencies]`. The JS analyser
  must not require Node.js as a runtime dependency.
- All NPM lockfile parsers handle empty / malformed input by returning
  an empty dict and logging a warning, never crashing.
- `write_manifest` for `package.json` must not parse-and-reserialise the
  JSON — that destroys formatting and key ordering. Use regex-based
  in-place rewriting.
- Backward compatibility: existing Python users see no change. NPM
  detection only activates when `package.json` is present.
- All changes must pass `pytest tests/` before this part is marked done.

---

## Task 3.1 — NPM adapter

**File:** `src/ecosystem/npm_adapter.py` (new)

### 3.1a — Discovery

```python
NPM_DEPENDENCY_CANDIDATES = [
    ("package.json", "package_json"),
]

NPM_LOCKFILE_CANDIDATES = [
    ("package-lock.json", "npm_lockfile"),
    ("yarn.lock",         "yarn_lockfile"),
    ("pnpm-lock.yaml",    "pnpm_lockfile"),
]
```

`find_manifest` returns the first matching `package.json` and detects
which of the three lockfile types is present alongside it. Both pieces
of information go on the returned `ManifestInfo`. If multiple lockfile
formats coexist (rare but happens during migrations), prefer them in
the order above.

### 3.1b — Manifest parser

`parse_manifest(content, "package_json")` returns a flat
`{name: declared_constraint}` dict drawn from all four sections:
`dependencies`, `devDependencies`, `peerDependencies`,
`optionalDependencies`. Use `json.loads` — `package.json` is required
to be valid JSON. On `JSONDecodeError`, raise `ValueError` with a clear
message naming the file and line number from the exception.

When a package appears in multiple sections, prefer in this order:
`dependencies > peerDependencies > optionalDependencies >
devDependencies`. Surface devDependencies entries last because they're
the ones least likely to ship to production but most likely to clutter
the output.

### 3.1c — Lockfile parsers

Three parsers, one per lockfile format, returning
`{package_name: resolved_version}`:

**`parse_npm_lockfile(content)` — package-lock.json v1, v2, v3:**

- v3: top-level `lockfileVersion: 3`, packages keyed under `packages`
  by relative path (`""` is the root, `"node_modules/<pkg>"` is each
  installed package). For each non-root entry, the package name is
  the substring after the last `node_modules/` and the version is
  `entry["version"]`.
- v2: same `packages` structure as v3. Same parser handles both.
- v1: `dependencies` is a tree of nested objects. Walk the tree
  recursively, emit `(name, version)` for each entry.

Detect by `lockfileVersion` field. Default to v1 parser if missing.

**`parse_yarn_lockfile(content)` — yarn 1 and yarn berry:**

- yarn berry: starts with `__metadata:` line, then YAML. Use `yaml.safe_load`.
  Packages are keyed by `<name>@npm:<version>` (or `<name>@workspace:...`).
- yarn 1: custom DSL. Each package block looks like:
  ```
  "package@^1.0.0":
    version "1.2.3"
    resolved "..."
  ```
  Parse line-by-line: package key on lines without leading whitespace;
  `version` on indented lines.

Detect by presence of `__metadata:` prefix (berry) or the absence of
it (yarn 1). PyYAML is already a dependency from earlier work.

**`parse_pnpm_lockfile(content)` — pnpm-lock.yaml:**

YAML. `yaml.safe_load`. Packages live under top-level `packages:`,
keyed as `/<name>@<version>(/<peer-deps-suffix>)`. Strip the leading
slash and any peer-deps suffix. The version is the trailing
`@<version>` chunk.

For all three: on parse failure, log a warning to stderr and return an
empty dict.

### 3.1d — `discover_installed`

Reads the lockfile if present (priority order from
`NPM_LOCKFILE_CANDIDATES`), otherwise walks
`node_modules/*/package.json` and `node_modules/@*/*/package.json` (for
scoped packages). Returns `{package_name: version}`.

### 3.1e — OSV ecosystem

```python
osv_ecosystem = "npm"
```

Part 2's OSV routing handles the rest.

### 3.1f — Currency check via npm registry

NPM has a free, no-key registry better than libraries.io for this:
`https://registry.npmjs.org/<package>`. Returns:

- `dist-tags.latest` — current version.
- `time.<version>` — release date map. Compute cadence from these.
- `versions.<version>.deprecated` — deprecation flag per version.

Implement `NpmRegistryClient` (mirror of `LibrariesIOClient`):

```python
class NpmRegistryClient:
    BASE_URL = "https://registry.npmjs.org"

    def __init__(self, cache=None, refresh=False, offline=False):
        ...

    def fetch_metadata(self, package: str) -> dict | None:
        """Cached GET. Returns None on 404 or network error."""
        ...
```

Cache responses for 6 hours (`ttl_hours=6`). Falls back to
`LibrariesIOClient` for any package the registry doesn't return.

`fetch_currency` builds `CurrencyRecord` from the metadata:
- `latest_version` from `dist-tags.latest`.
- `latest_release_date` from `time[latest_version]`.
- `release_cadence_days`: compute mean delta between consecutive
  release timestamps (last 10 releases).
- `deprecated`: True if the latest version's entry has a `deprecated`
  field.
- `signals`: append `"deprecated"` if the latest is deprecated; append
  `"unmaintained"` if no release in the last 18 months.

### 3.1g — Dependency graph

For NPM, the lockfile already contains the complete resolved
dependency tree. No external API call is needed.

`build_graph` reads the lockfile and emits `GraphEdge(parent, child)`
for every declared dependency in every package's lockfile entry. The
"parent" is the package name (or the project name for root-level
deps). When `include_transitive=False`, only emit edges from the root.
When `True`, emit the full tree.

If no lockfile is present, fall back to the manifest: emit only direct
edges from the project to declared dependencies, and log a note that
transitive analysis requires a lockfile.

### 3.1h — Manifest writer

`write_manifest` for `package_json` rewrites the version constraint in
place. Use a regex that matches the package's line under the relevant
section and replaces only the version string:

```python
# Pattern: "<package>": "<version-spec>"
# Allow whitespace, scoped names, and any valid version spec characters.
pattern = re.compile(
    r'("(?:' + re.escape(package_name) + r')"\s*:\s*")'
    r'[^"]*'
    r'(")'
)
new_content = pattern.sub(rf'\g<1>{new_version}\g<2>', original_content, count=1)
```

For each upgrade, locate the package's entry across all four sections.
If found in multiple sections, update each one. Atomic write via
`<path>.tmp` then `os.replace`.

Do not parse the JSON. Preserve everything else: indentation, key
ordering, trailing commas (which are valid in some npm tooling), and
comments (which JSON doesn't formally support but JSON5-compatible
tools accept).

### 3.1i — Lockfile regeneration

Detects which lockfile type is present and runs the corresponding
tool:

- `npm_lockfile` → `npm install --package-lock-only`
- `yarn_lockfile` → `yarn install --mode=update-lockfile` (yarn berry)
  or `yarn install --frozen-lockfile=false` (yarn 1). Detect by
  re-reading the lockfile's first line.
- `pnpm_lockfile` → `pnpm install --lockfile-only`

If the relevant tool isn't on PATH:

```python
ApplyOutcome(
    success=False,
    output=(
        f"{tool} not found on PATH. Install {tool} or run "
        f"'{tool} install' manually before deploying."
    ),
    files_modified=[],
)
```

The implementation pattern matches `PythonAdapter._run_lock_tool` from
Part 2 — same `shutil.which` check, same subprocess call, same
`ApplyOutcome` shape. If the existing helper is reusable, lift it to
a shared utility module rather than duplicate.

### 3.1j — Install

Detection order: `npm install`, `yarn install`, `pnpm install` based on
which lockfile type was detected. If no lockfile is present, default to
`npm install`. Mirror `PythonAdapter.install`'s shape — capture
combined stdout + stderr, return `ApplyOutcome` with the full output.

### 3.1k — Dry-run validation

NPM tools' dry-run support is uneven. For v0.7, implement as a
two-step check:

1. **Registry HEAD checks.** For each upgrade target, send
   `HEAD https://registry.npmjs.org/<package>/<version>`. Verify all
   return 200. Cache the result for 1 hour.
2. **Peer-dependency conflict check.** For each upgrade, fetch the
   target version's metadata. Cross-reference declared
   `peerDependencies` against the proposed package set. Flag any
   conflict (e.g. `react@19` requires `react-dom@>=19` but the
   selection still has `react-dom@18`).

If both checks pass, return `(True, "")`. Otherwise return
`(False, <message naming the conflict or missing version>)`. Full
`npm install --dry-run` validation is a v0.8 enhancement.

### 3.1l — Register the adapter

**File:** `src/ecosystem/__init__.py`

Add `NpmAdapter` to the registry:

```python
from .npm_adapter import NpmAdapter

REGISTRY: dict[str, EcosystemAdapter] = {
    "python": PythonAdapter(),
    "npm": NpmAdapter(),
}
```

The polyglot ordering rule from Part 1 applies: when both
`pyproject.toml` and `package.json` exist at the same depth, Python
wins by registry order. Log a warning naming both adapters and noting
that `--ecosystem` (Part 4) is the override.

### 3.1m — Tests

All in `tests/test_smoke.py`. Fixture files in `tests/fixtures/npm/`.

- `test_npm_parse_package_json_collects_all_dep_sections` — fixture
  with all four sections; assert all packages present, deduplicated.
- `test_npm_parse_package_lock_v3` — fixture
  `tests/fixtures/npm/package-lock-v3.json`.
- `test_npm_parse_package_lock_v1` — fixture
  `tests/fixtures/npm/package-lock-v1.json`.
- `test_npm_parse_yarn_lock_v1` and `test_npm_parse_yarn_lock_berry`.
- `test_npm_parse_pnpm_lock`.
- `test_npm_lockfile_parsers_return_empty_dict_on_malformed_input` —
  feed garbage strings to each parser; assert empty dict, no
  exception.
- `test_npm_adapter_writes_package_json_preserving_formatting` —
  fixture with custom indentation and key ordering; verify the
  regex-based writer doesn't reorder keys or change indentation.
- `test_npm_adapter_writes_package_json_updates_all_sections` —
  fixture where the same package appears in `dependencies` and
  `devDependencies`; assert both are updated.
- `test_npm_registry_client_returns_currency_record` — mock the HTTP
  response for `https://registry.npmjs.org/<pkg>`; assert
  `CurrencyRecord` shape.
- `test_npm_lockfile_regeneration_returns_clear_error_when_npm_missing` —
  monkeypatch `shutil.which` to return `None` for `"npm"`; assert
  `ApplyOutcome.success is False` and `"npm not found on PATH"` in
  `output`.
- `test_npm_dry_run_validate_rejects_nonexistent_version` — mock
  registry responses so one HEAD returns 404; assert
  `(False, message)` and the message names the missing package +
  version.
- `test_detect_adapter_chooses_npm_for_package_json_only`,
  `test_detect_adapter_polyglot_warns_and_prefers_python` (extends
  the Part 1 detection tests).

---

## Task 3.2 — JS/TS usage analyser

**File:** `src/ecosystem/js_usage.py` (new)

Pure-Python AST analysis using `tree_sitter`. Add to
`pyproject.toml`:

```toml
[project]
dependencies = [
    ...,
    "tree-sitter>=0.21",
    "tree-sitter-javascript>=0.21",
    "tree-sitter-typescript>=0.21",
]
```

### 3.2a — File walker

Walks every `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` file in the
source tree. Excludes:

- `node_modules/`
- `dist/`, `build/`, `out/`, `.next/`, `.nuxt/`, `coverage/`
- Any directory listed in the project's `.gitignore` (parse the
  gitignore and apply the patterns; if parsing fails, log a warning
  and skip gitignore filtering).
- Hidden directories (prefixed with `.`) other than `.next` /
  `.nuxt` already handled.

For each file, parse the AST with the appropriate tree-sitter grammar
based on extension:

- `.ts`, `.tsx` → `tree_sitter_typescript`.
- everything else → `tree_sitter_javascript`.

### 3.2b — Symbol extraction

Collect symbols from these AST node types:

**Static imports** (`import_statement`):
- `import x from "pkg"` → record symbol `default` for package `pkg`.
- `import { a, b } from "pkg"` → record symbols `a`, `b`.
- `import { a as alias } from "pkg"` → record symbol `a` (the
  imported name, not the local alias).
- `import * as x from "pkg"` → record symbol `*` (special marker;
  the rendering logic in `reporting.py` already handles this).

**CommonJS requires**:
- `const x = require("pkg")` → record symbol `default`.
- `const { a } = require("pkg")` → record symbol `a`.

**Dynamic imports with literal arguments**:
- `import("pkg")` / `await import("pkg")` where the argument is a
  string literal → record symbol `*`.

**Unresolved cases** (added to `UsageResult.unresolved`):

- Dynamic `require(variable)` / `import(variable)` →
  `{"flag": "dynamic_require", "package": None, "source_file": ..., "line": ...}`.
- Re-exports (`export * from "pkg"`) →
  `{"flag": "reexport", "package": "pkg", "source_file": ..., "line": ...}`.
- TypeScript namespace member access (`x.foo()` after
  `import * as x`) → `{"flag": "member_access", "package": "pkg", ...}`.

### 3.2c — Bare specifier handling

`"foo"`, `"foo/bar"`, `"@scope/foo"`, `"@scope/foo/sub"` all resolve
to the package portion: `foo`, `foo`, `@scope/foo`, `@scope/foo`.
Strip the sub-path. Skip relative imports (`./x`, `../x`) and
absolute paths (`/x`). Skip Node.js built-in modules (maintain a
small list: `fs`, `path`, `crypto`, `os`, `child_process`, `util`,
`stream`, `events`, `http`, `https`, `url`, `querystring`, `buffer`,
`process`, `assert`, `zlib`, `tls`, `net`, `dns`, `worker_threads`).

### 3.2d — Wire into `NpmAdapter.analyse_usage`

```python
def analyse_usage(self, source: Path, packages: dict) -> UsageResult:
    from .js_usage import analyse_project as _js_analyse
    return _js_analyse(source, packages=packages)
```

Mirror Python's adapter wrapper.

### 3.2e — Tests

Fixture files in `tests/fixtures/npm/usage/`:

- `test_js_usage_collects_named_imports` — fixture
  `named_imports.js`: `import { foo, bar } from "lodash";`. Assert
  records for both symbols, package `lodash`.
- `test_js_usage_resolves_scoped_packages` — fixture: `import x from
  "@aws-sdk/client-s3";`. Assert package `@aws-sdk/client-s3`.
- `test_js_usage_resolves_subpath_specifiers` — fixture: `import x
  from "lodash/get";`. Assert package `lodash` (sub-path stripped).
- `test_js_usage_records_commonjs_require` — fixture using
  `require()`.
- `test_js_usage_flags_dynamic_require` — fixture: `const x =
  require(name);`. Assert one entry in `unresolved` with flag
  `"dynamic_require"`.
- `test_js_usage_skips_relative_imports` — fixture: `import x from
  "./local";`. Assert no records.
- `test_js_usage_skips_node_builtins` — fixture: `import { readFile
  } from "fs";`. Assert no records.
- `test_js_usage_handles_typescript_syntax` — fixture `.ts` file
  with type annotations and an `import type { ... }`; assert
  imports captured (including type-only imports — they're still
  symbol references and a vulnerable type can be a real signal).
- `test_js_usage_skips_node_modules_and_dist` — fixture project
  with `node_modules/foo/index.js` and `dist/bundle.js` containing
  imports; assert the walker prunes both.
- `test_js_usage_respects_gitignore` — fixture project with a
  `.gitignore` listing `generated/`, plus a `generated/x.js` file;
  assert no records from `generated/`.

---

## Definition of Done — Part 3

- [ ] `pytest tests/` passes with zero failures and zero errors.
- [ ] `changes-ai --source <npm-project> --cve-scan` discovers
  `package.json`, parses any present lockfile, queries OSV with
  `ecosystem: "npm"`, and prints findings. Tested against at least
  one real public NPM project (manually).
- [ ] `changes-ai --source <npm-project> --all` produces a remediation
  plan with NPM upgrade candidates.
- [ ] `tree-sitter`, `tree-sitter-javascript`,
  `tree-sitter-typescript` are listed in `pyproject.toml`
  `[project.dependencies]`.
- [ ] `from src.ecosystem import REGISTRY; "npm" in REGISTRY` returns
  `True`.
- [ ] Polyglot directory (`pyproject.toml` + `package.json` at the
  same depth) prints a warning naming both adapters and proceeds with
  Python.
- [ ] All Python tests from Parts 1 and 2 still pass without
  modification.
- [ ] No CHANGELOG entry yet — Part 4 writes the consolidated v0.7.0
  entry.
