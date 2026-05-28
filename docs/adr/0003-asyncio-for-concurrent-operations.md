# 3. AsyncIO for Concurrent Operations

Date: 2026-05-25

## Status

Accepted

## Context

SBOM generation and processing involves many I/O-bound operations: fetching OCI manifests
via oras, downloading SBOMs from TPA, verifying signatures with cosign, and uploading
results. Processing snapshots with many images sequentially would be prohibitively slow
in CI pipelines.

## Decision

The entire Mobster codebase uses Python's asyncio for concurrency. All `Command`
implementations are async, the CLI entry point runs via `asyncio.run()`, and I/O-bound
operations use async subprocess helpers (`utils.py`). Concurrency limits are exposed as
`--concurrency` flags on commands that fan out across multiple images.

## Consequences

- Snapshot processing and bulk uploads scale to many images without threading complexity
- All new commands and utilities must be written as async functions
- Synchronous libraries (e.g. `spdx-tools`) are called directly since they are CPU-bound
  and do not block the event loop significantly
- Testing async code requires `pytest-asyncio`
