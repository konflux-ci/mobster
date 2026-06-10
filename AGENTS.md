# Mobster

Python tool for generating and managing SBOMs (SPDX and CycloneDX) in the Konflux CI/CD platform.

Guidance for AI assistants in this repo. See [CONTRIBUTING.md](CONTRIBUTING.md) for full workflow and setup and [README.md](README.md) for Konflux context and usage examples.

## Key Conventions

- **All CLI commands implement the `Command` ABC** `execute()` and `save()` async methods — never add command logic outside this pattern.
- **Both SPDX and CycloneDX are supported.** Most generate commands default to CycloneDX;
- **Async throughout.** All I/O-bound operations use `asyncio`. Use `utils.py` helpers for subprocess calls instead of `subprocess` directly.
- **External tool outputs are parsed, not reimplemented.** Syft generates raw SBOMs; mobster parses and enriches them. Cosign and oras are invoked as subprocesses.
- **Coverage must stay at 95%+**.
- **Type annotations are required.** Use `mypy` for static type checking; run `tox -e mypy` before submitting PRs.
- **Documentation for new features is required.** Update relevant parts of /docs/ and add docstrings to new code, docstring don't need types if the function is already fully typed.
- **Project uses poetry for dependency management.** Use `poetry add` to add new dependencies and update `pyproject.toml` accordingly. Don't modify lock files directly.

## Architecture

- `tekton/` contains entry points used as Tekton task steps (`process_component_sboms`, `process_product_sbom`). These orchestrate augment + upload + S3 push and use config beyond the standard CLI — don't confuse them with CLI commands.
- `cli.py` only sets up argparse; `main.py` is the entry point that calls `args.func` (a `Command` subclass) and runs `execute()` then `save()`.
- Generic SBOM changes should be done in centralized place and inherited by all relevant commands.
- Mobster is built by Konflux CI and the result is available in the Quay registry.

## PR Conventions

- Run `tox` (or at minimum `tox -e ruff` and `tox -e mypy`) before submitting.
- Integration tests require `docker compose up -d` and `tox -e test-integration` — CI runs them separately from unit tests.
- All checks (`tox` and integration tests) need to pass before a PR can be merged.
- Coverage gates are enforced in CI; new code needs tests.
