# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mobster is a Python tool for generating and managing Software Bill of Materials (SBOMs) in SPDX and CycloneDX formats. It is used within the Konflux CI/CD platform to produce SBOMs for OCI images, OCI indexes, product releases, modelcar images, OCI artifacts, and PKO packages. SBOMs can be uploaded to Trusted Profile Analyzer (TPA) or stored in S3.

## Setup

```bash
# Install Poetry, then:
poetry install
poetry shell
```

## Common Commands

### Testing
```bash
tox -e test                              # Run all unit tests (excludes integration)
tox -e test -- -k test_name             # Run a specific test by name
tox -e test -- -v                        # Verbose output
tox -e test-integration                  # Run integration tests (requires docker compose up -d)
```

Coverage must stay at 95%+. Slow tests are marked with `@pytest.mark.slow` and excluded by default.

### Linting & Formatting
```bash
tox -e ruff                  # Check formatting and lint (ruff)
tox -e ruff-fix              # Auto-fix formatting and lint issues
tox -e pylint                # Run pylint
tox -e mypy                  # Run mypy (strict mode)
tox -e bandit                # Run bandit security checks
tox -e yamllint              # Lint YAML files
tox                          # Run all checks (test, ruff, pylint, bandit, mypy, yamllint, pip-audit, hadolint)

# Single-file checks (fast feedback):
tox -e ruff -- src/mobster/some_file.py  # lint one file
tox -e mypy -- src/mobster/some_file.py  # type-check one file
```

### Build
```bash
podman build -t <image_name> .    # Build container image
podman run -it <image_name>       # Run container
```

## Architecture

### Package Layout

```
src/mobster/
  cli.py              # argparse CLI setup
  main.py             # Entry point: parses args, runs async command
  cmd/                # Command implementations (Command ABC pattern)
    base.py           # Abstract Command base class (execute + save)
    generate/         # SBOM generation commands per artifact type
      oci_image/      # OCI image SBOM generation (most complex)
        contextual_sbom/  # Contextualization: matches packages to base/builder images
    augment/          # Augments existing SBOMs with release metadata, CPEs, signing
    upload/           # Upload SBOMs to TPA (with OIDC auth)
    download/         # Download SBOMs from TPA
    delete/           # Delete SBOMs from TPA
  sbom/               # SPDX and CycloneDX model utilities
    spdx.py           # SPDX document/package builders
    cyclonedx.py      # CycloneDX document/component builders
    merge.py          # Merge multiple SBOM documents
  oci/                # OCI registry interactions
    __init__.py       # oras-based manifest fetch, docker auth file handling
    artifact.py       # OCI artifact helpers
    cosign/           # cosign signature verification (static key, keyless, rekor)
  tekton/             # Tekton task entry points (component + product processing)
  regenerate/         # Batch SBOM regeneration utilities
  artifact.py         # Artifact dataclass (oci-copy schema)
  image.py            # Image dataclass with pullspec/digest parsing
  release.py          # ReleaseId type
  syft.py             # Syft SBOM parsing utilities
  utils.py            # Async subprocess helpers
```

### Command Pattern

All CLI commands implement `Command` (abstract base in `cmd/base.py`) with two async methods:
- `execute()` — perform the operation, store result
- `save()` — write output to disk or remote

The CLI dispatcher in `main.py` calls both sequentially after `argparse` resolves `args.func` to a `Command` subclass.

### SBOM Generation Flow (OCI Image)

The most complex path: `generate oci-image` merges Syft and Hermeto SBOMs, adds base image relationships from a parsed Dockerfile, optionally contextualizes packages to their source base/builder image, and validates the result.

### Tekton Entry Points

`process_component_sboms` and `process_product_sbom` scripts (in `tekton/`) are used as Tekton task steps. They orchestrate augment + upload + S3 push in a single call and use S3/Atlas-specific config beyond the standard CLI.

### External Tools

- **oras** — fetching OCI manifests
- **cosign** — signature verification for image provenance
- **syft** — generating raw SBOMs from container images (output is parsed by mobster)

## Pattern References

Common change types and reference implementations to follow:

- **New generate command**: see `src/mobster/cmd/generate/modelcar.py` (simplest example of a full generate command)
- **New augment step**: see `src/mobster/cmd/augment/` for the augment command pattern
- **New CLI argument**: see `src/mobster/cli.py` — add argument to the relevant `*_command_parser` function and wire it to the `Command` subclass via `set_defaults`
- **New SBOM utility (SPDX)**: see `src/mobster/sbom/spdx.py`
- **New SBOM utility (CycloneDX)**: see `src/mobster/sbom/cyclonedx.py`

### SBOM Formats

Both SPDX (`spdx-tools` library) and CycloneDX (`cyclonedx-python-lib`) are supported. Most generation commands default to CycloneDX; OCI image generation produces SPDX.
