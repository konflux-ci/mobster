# 2. Dual SBOM Format Support (SPDX and CycloneDX)

Date: 2026-05-25

## Status

Accepted

## Context

Two SBOM formats have broad industry adoption: SPDX (ISO/IEC 5962:2021) and CycloneDX.
Konflux CI pipelines and downstream consumers (e.g. Trusted Profile Analyzer) may expect
either format depending on the artifact type and pipeline stage.

## Decision

Mobster supports both SPDX and CycloneDX formats. The `sbom/` package provides separate
modules for each (`spdx.py`, `cyclonedx.py`) backed by their respective libraries
(`spdx-tools` and `cyclonedx-python-lib`). OCI image generation produces SPDX; most other
generation commands default to CycloneDX with an `--sbom-type` flag to switch.

## Consequences

- Consumers can receive SBOMs in their preferred format without format conversion
- Two sets of model utilities must be maintained in parallel
- Cross-format merging is not supported; all inputs to a merge operation must be in the
  same format
- New features (e.g. new relationship types) must be implemented in both format modules
