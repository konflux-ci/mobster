---
name: lint-and-verify
description: Use when checking formatting, linting, type errors, or security issues in the mobster repository — ruff, pylint, mypy, bandit, yamllint, pip-audit
---

# Lint and Verify

## Quick reference

| Check | Command | Single-file |
|---|---|---|
| Format + lint | `tox -e ruff` | `tox -e ruff -- src/mobster/file.py` |
| Auto-fix format/lint | `tox -e ruff-fix` | `tox -e ruff-fix -- src/mobster/file.py` |
| Static analysis | `tox -e pylint` | — |
| Type check (strict) | `tox -e mypy` | `tox -e mypy -- src/mobster/file.py` |
| Security scan | `tox -e bandit` | — |
| YAML lint | `tox -e yamllint` | — |
| Dependency audit | `tox -e pip-audit` | — |
| All checks | `tox` | — |

## Fast feedback loop

For tight iteration, run single-file checks after each change:

```bash
tox -e ruff -- src/mobster/file.py   # format + lint (seconds)
tox -e mypy -- src/mobster/file.py   # type check (seconds)
```

Run the full suite (`tox`) before opening a PR.

## Key constraints

- **mypy runs in strict mode** — all functions need type annotations, `Any` usage must be explicit
- **ruff** enforces both formatting (like black) and linting (like flake8) — use `ruff-fix` to auto-apply safe fixes
- **bandit** flags common security anti-patterns (shell injection, hardcoded secrets, unsafe deserialization)
