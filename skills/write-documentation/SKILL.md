---
name: write-documentation
description: Use when writing, updating, or adding documentation for mobster commands, features, or developer internals — covers file placement and mkdocs.yml nav rules
---

# Write Documentation

## Rules at a Glance

| Documentation type | Location in `docs/` | Add to `mkdocs.yml`? |
|---|---|---|
| Public CLI command | `docs/sboms/<command>.md` | **Yes** |
| Other public feature | `docs/sboms/<topic>.md` or `docs/<topic>.md` | **Yes** |
| Developer / internal | `docs/` (any path) | **No** |
| ADR | `docs/adr/<nnnn>-<slug>.md` | **No** |

## Public Command Documentation

Place in `docs/sboms/` and add a nav entry to `mkdocs.yml`.

**Example:** adding `generate pko-package`:

1. Create `docs/sboms/pko_package.md`
2. Add to `mkdocs.yml` under the relevant section:

```yaml
nav:
  - "SBOM content types":
      - "PKO Package": "sboms/pko_package.md"   # ← add here
```

Follow the structure of an existing command doc (e.g., `docs/sboms/oci_image.md`):
- One-line description of what the command does
- Architecture / how it works (if non-obvious)
- Usage example (full CLI invocation)
- List of arguments with short descriptions

## Developer Documentation

Place anywhere in `docs/` that makes sense. **Do not add to `mkdocs.yml`.**

Typical locations:
- `docs/adr/` — Architecture Decision Records (numbered `NNNN-slug.md`)
- `docs/development-environment.md`, `docs/integration-testing.md`, `docs/release.md` — already exist; extend them rather than creating new top-level files when possible

## mkdocs.yml Nav Structure

Current top-level sections:

```
Overview
SBOM lifecycle       ← lifecycle, augmentation, upload, download, delete
SBOM content types   ← one page per generate subcommand
SBOM formats
Admin & developer guides
```

New public command pages go under **"SBOM content types"**.
New public non-command pages (e.g., a new lifecycle concept) go under **"SBOM lifecycle"** or a new section if genuinely distinct.

## Common Mistakes

- Adding developer docs (ADRs, internal design notes) to `mkdocs.yml` — they should remain discoverable only by reading the repo.
- Creating a new top-level nav section for a single page — nest under an existing section first.
- Skipping the arguments table in command docs — all CLI flags should be listed with a short description.
