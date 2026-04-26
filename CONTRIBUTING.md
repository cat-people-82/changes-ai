# Contributing

Thanks for considering a contribution to Changes AI.

Changes AI is in public preview. Contributions should keep the CLI predictable,
avoid broad refactors, and preserve clear behavior for security-sensitive
workflows.

## Development Setup

```bash
git clone https://github.com/pzanna/changes-ai.git
cd changes-ai
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Running Checks

Run the smoke tests from the repository root:

```bash
python -m pytest
python -m compileall -q src tests
```

For a local end-to-end smoke run, use a temporary cache path so generated state
does not land in the project directory:

```bash
python -m src.changes_ai --source . --output table --cache-db /tmp/changes-ai.sqlite
```

## Pull Request Guidelines

- Keep changes scoped to one behavior or release concern.
- Add or update tests for user-visible behavior, parser behavior, CLI behavior,
  and security-sensitive logic.
- Do not commit `.env`, cache databases, cloned repositories, generated reports,
  or local virtual environments.
- Document new environment variables, outbound network calls, output formats,
  or privacy implications in `README.md`.
- Prefer deterministic local logic for validation and scoring; use LLM calls for
  synthesis where the app already expects model-dependent output.

## Commit and Release Notes

Use clear commit messages that describe the user-facing change. For release
changes, update `CHANGELOG.md` under an `Unreleased` section or the target
version section.

## License

By contributing, you agree that your contribution is provided under the project
license: GPL-3.0-or-later.
