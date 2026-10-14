# Small merge examples

Artificial SBOM fixtures for merge behavior.
Each SPDX case has `*.bom.json` inputs and `expected.bom.json`.

| Case | What it shows |
|------|----------------|
| `spdx/remap-relationships` | Duplicate `pkg:pypi/foo@1.0.0`: Hermeto package kept; Syft `root CONTAINS syft-foo` becomes `root CONTAINS hermeto-foo`; document annotations (e.g. `release_id`) kept; Syft package annotation remapped onto Hermeto foo |
| `spdx/multi-syft` | Two Syft SBOMs; shared npm package kept from the first; second SBOM's CONTAINS remapped to the kept id |
| `spdx/alt-purl-match` | Hermeto VCS PyPI preferred over Syft registry; Hermeto `pkg:npm/...#foo/eggs` matches Syft `pkg:npm/foo/eggs`; both CONTAINS remapped |
| `spdx/golang` | With Hermeto: Syft `.localmod@(devel)` dropped; Syft `#v2` matches Hermeto `/v2` (CONTAINS remapped); Syft-only remote kept |
| `cyclonedx/prefer-and-remap` | Hermeto `foo` preferred over Syft duplicate; Syft-only `bar` kept; `syft-foo→syft-bar` remapped to `hermeto-foo→syft-bar`; `metadata.tools.components` from Syft and Hermeto are merged |
