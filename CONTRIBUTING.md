# Contributing to Mobster

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Getting Started

1. Fork the repository and clone your fork
2. Set up your local environment — see [docs/development-environment.md](docs/development-environment.md)
3. Install pre-commit hooks (includes gitleaks secret detection and conventional commit linting):
   ```bash
   pre-commit install --hook-type commit-msg
   pre-commit install
   ```

## Making Changes

- Create a branch from `main` for your change
- Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format for commit messages:
  - `feat: add support for OCI artifact SBOMs`
  - `fix: correct purl normalization for rpm packages`
  - `docs: update augment command examples`
- Keep commits focused — one logical change per commit
- For significant design decisions, consider adding an [ADR](docs/adr/) (see existing ADRs for format)

## Running Checks Locally

See [docs/development-environment.md](docs/development-environment.md) for the full list of tox commands, code formatting, testing, and integration test setup. Test coverage must stay at **95%+**.

## Submitting a Pull Request

1. Push your branch and open a PR against `main`
2. Fill in the PR template — include what changed and how it was tested
3. Ensure all CI checks pass
4. Address review feedback; a maintainer will merge once approved

## Reporting Issues

Use the GitHub issue templates:
- **Bug report** — for unexpected behavior
- **Feature request** — for new functionality

## License

By contributing, you agree your changes will be licensed under the [Apache License 2.0](LICENSE).
