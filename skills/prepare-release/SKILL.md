---
name: prepare-release
description: Use when preparing a new release of mobster — release-please, version bump, GitHub release, PyPI, container image
---

# Prepare Release

Mobster uses `release-please` CLI for versioning and release notes, GitHub Actions for PyPI, and Konflux for the container image.

## Prerequisites

```bash
git pull upstream main --tags
export GITHUB_TOKEN=<your_personal_access_token>   # needs repo scope
```

Install `release-please` CLI if not already installed — see [release-please CLI docs](https://github.com/googleapis/release-please/blob/main/docs/cli.md#running-release-please-cli).

## Steps

### 1. Open a release PR

```bash
make open-release-pr           # creates PR with version bump + changelog
make open-release-pr-dry-run   # dry-run: preview changes without creating PR
```

Review the generated PR and merge it into `main`.

### 2. Create GitHub release and tag

After the PR is merged:

```bash
make github-release            # tags commit, pushes tag, creates GitHub release
make github-release-dry-run    # dry-run preview
```

This:
- Creates a `vX.Y.Z` tag and pushes it to the remote
- Creates a GitHub release with auto-generated release notes
- Triggers the PyPI release GitHub Action

### 3. Verify downstream releases

**PyPI** — triggered automatically by the `vX.Y.Z` tag push via GitHub Actions. Check https://pypi.org/project/mobster/ for the new version.

**Container image** — Konflux builds and publishes on every merged PR:
- Intermediate: `quay.io/redhat-user-workloads/the-collective-tenant/mobster-f7a65`
- Public: `quay.io/konflux-ci/mobster`
