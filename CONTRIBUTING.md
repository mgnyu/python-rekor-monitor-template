# Contributing

Thanks for helping improve this project. This guide covers how to report issues and submit changes.

## Reporting issues

- Search existing issues first.
- For bugs, include the command you ran, the full output, the expected behaviour, and your Python version.
- When the problem is in a specific place, link to the line(s): click the line number on GitHub → **Reference in new issue**.
- Security problems: **do not open an issue**. Follow [SECURITY.md](SECURITY.md).

## Development setup

```bash
poetry install
pipx install pre-commit
pre-commit install          # requires trufflehog on PATH
```

## Making changes

1. Create a branch from `main`: `git checkout -b fix/short-description`
2. Keep each pull request focused on one change.
3. `main` is protected: all changes go through a pull request, and history must stay linear (rebase, don't merge `main` into your branch).

## Coding style

- Formatting: `ruff format` (PEP 8, line length 88).
- Linting: `ruff check` must report **0 errors**.
- Types: all functions are fully type-annotated. `mypy` runs in strict mode and must pass.
- Security: `bandit` must report no issues. Don't silence findings with `# nosec` without explaining why in the PR.
- Add docstrings to public functions. Use clear names, not single letters such as `l`.
- Failures must raise or exit non-zero. Never print an error and continue as if verification passed.

## Testing requirements

- Add or update tests in `tests/` for every bug fix and feature.
- Tests must not make real network calls. Use the `rekor` fixture in `tests/conftest.py`.
- `poetry run pytest` must pass, and total coverage must stay **≥ 75 %** (enforced by `fail_under`).

## Before you open a pull request

```bash
poetry run ruff format .
poetry run ruff check .
poetry run mypy
poetry run bandit -c pyproject.toml -r .
poetry run pytest
```

In the PR description, say what changed and why, and link the issue it fixes (e.g. `Closes #12`). A maintainer listed in [CODEOWNERS](.github/CODEOWNERS) will review it.

## Commits

- Write messages in the imperative mood ("Fix shard index in inclusion proof").
- Never commit secrets, keys, or `.env` files. The pre-commit hook blocks commits containing detected secrets. If it fires, remove the secret; don't bypass it with `--no-verify`. If a secret was ever pushed, rotate it.

## License

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
