---
name: run-integration-tests
description: Use when running integration tests in the mobster repository — requires docker compose, tests OCI registry interactions, cosign, syft, and TPA upload flows
---

# Run Integration Tests

## Prerequisites

Integration tests require a running local registry and supporting services:

```bash
docker compose up -d
```

Check services are healthy before running tests:

```bash
docker compose ps
```

## Commands

```bash
tox -e test-integration              # all integration tests
tox -e test-integration -- -k name  # single test by name
tox -e test-integration -- -v       # verbose output
```

## What integration tests cover

- OCI registry interactions (push/pull via `oras`)
- `cosign` signature verification flows
- `syft` SBOM generation against real images
- TPA upload/download/delete against a local mock

These tests are excluded from unit test runs and coverage gates — they verify end-to-end flows, not individual functions.

## Teardown

```bash
docker compose down
```

## Common mistakes

- Running without `docker compose up -d` first — tests will fail with connection errors, not a helpful message
- Running `tox -e test` expecting integration tests to be included — they are not; use `tox -e test-integration`
