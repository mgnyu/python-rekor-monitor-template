# Python Rekor Monitor

A command-line tool that checks the [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log. It can:

- **Fetch the latest checkpoint** (signed tree head) from the public Rekor instance.
- **Verify inclusion** of an artifact. It checks the artifact's signature against the certificate in its Rekor entry and verifies the entry's Merkle inclusion proof offline.
- **Verify consistency** between an older checkpoint and the current one. This proves the log has only been appended to, not rewritten.

Built for NYU CS-GY 9223 Software Supply Chain Security.

## Installation

Requires Python 3.10+ and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/mgnyu/python-rekor-monitor-template.git
cd python-rekor-monitor-template
poetry install
```

## Usage

```bash
# Print the latest checkpoint
poetry run python main.py -c

# Verify that artifact.md is signed and included in the log at a given index
poetry run python main.py --inclusion 3078593138 --artifact artifact.md

# Verify an older checkpoint is consistent with the latest one
poetry run python main.py --consistency \
  --tree-id 1193050959916656506 \
  --tree-size 5114308 \
  --root-hash aa9f28964e1205576a05cbc6b66222124142b9fb15d803f55d8cbb1d74e766d7
```

Add `-d` to any command for debug output. Debug JSON is written to `debug_output/`.

Use the global `logIndex` from your bundle (`verificationMaterial.tlogEntries[0].logIndex`), not the shard-local index inside `inclusionProof`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All requested checks passed |
| 1 | A verification failed, or Rekor/network/input error |
| 2 | Invalid command-line arguments |

## Development

```bash
poetry install                     # runtime + dev tools
pipx install pre-commit            # or: pip install pre-commit
pre-commit install                 # enable the trufflehog secret-scan hook
```

The hook needs the [trufflehog](https://github.com/trufflesecurity/trufflehog#floppy_disk-installation) binary on your `PATH`.

| Task | Command |
|------|---------|
| Format | `poetry run ruff format .` |
| Lint | `poetry run ruff check .` |
| Type-check | `poetry run mypy` |
| Security scan | `poetry run bandit -c pyproject.toml -r .` |
| Tests + coverage | `poetry run pytest` (HTML report in `htmlcov/`) |

All tool settings live in `pyproject.toml`. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Project layout

```
main.py            CLI and Rekor API calls
merkle_proof.py    RFC 6962 inclusion and consistency proof verification
util.py            certificate and signature helpers
scripts/           helper that creates artifact.md
tests/             pytest suite (Rekor is mocked; no network needed)
```

## License

[MIT](LICENSE)
