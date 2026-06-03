---
name: run-unit-tests
description: Use when running, filtering, debugging, or adding unit tests in the mobster repository — tox, pytest, coverage
---

# Run Unit Tests

## Commands

```bash
tox -e test                              # all unit tests
tox -e test -- -k test_name             # single test by name
tox -e test -- -k "TestClass"           # all tests in a class
tox -e test -- path/to/test_file.py     # single file
tox -e test -- -v                        # verbose output
tox -e test -- --cov-report=term-missing # show uncovered lines
```

## Coverage

Must stay at **95%+**. If your change drops coverage, add tests before committing. Use `--cov-report=term-missing` to identify uncovered lines.

## Test layout

Tests mirror the source tree under `tests/`:

```
tests/
  cmd/generate/oci_image/   # mirrors src/mobster/cmd/generate/oci_image/
  sbom/                     # mirrors src/mobster/sbom/
  oci/                      # mirrors src/mobster/oci/
  ...
```

Place new test files in the matching subdirectory. Name them `test_<module_name>.py`.
