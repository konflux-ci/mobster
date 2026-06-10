# Mobster

The Mobster project is a Python-based tool and ecosystem to
work with SBOM (Software Bill of Materials) documents. Its goal is to provide
unified interface for generating, manipulating and consuming SBOM documents
in various formats.

The tools is designed to cover a whole lifecycle of SBOM documents.
The major stages are:

- **Generation**: Generate SBOMs document from various sources (Syft, Hermeto, etc.)
- **Augmentation**: Augment SBOM documents with additional information that are not
  present in the phase of generation. This phase is usually done in the
  release phase where we know more information about the software.
- **Validation**: Validate a quality of the SBOM document in different stages
  of the lifecycle. The validation is done by the [Product Security team
  guidelines](https://github.com/RedHatProductSecurity/security-data-guidelines/tree/main).
- **Distribution**: Distribute the SBOM document to various set of locations (e.g. Trusted
  Profile Analyzer, container registry, etc.)

## Getting started

To use the Mobster tool, you need to install it first. There are multiple ways to install
the tool:

### Using pip

```bash
pip install mobster
mobster --help
```
### Using container image

```bash
podman pull quay.io/konflux-ci/mobster:latest
podman run -it quay.io/konflux-ci/mobster:latest mobster --help
```

#### Additional dependencies
Some features of Mobster require additional dependencies to be installed outside of Python
ecosystem. To use those features, you need to install the following tools:

- [**oras**](https://github.com/oras-project/oras): Used for pushing and pulling SBOM documents to/from OCI registries.
- [**cosign**](https://github.com/sigstore/cosign): Used for signing and verifying SBOM documents in OCI registries.
- [**syft**](https://github.com/anchore/syft): Used for generating SBOM documents from container images and filesystems.

## Usage

```bash
# Generate an SBOM for an OCI image (merging Syft and Hermeto outputs)
mobster generate --output sbom.json oci-image \
  --from-syft syft-sbom.json \
  --image-pullspec registry.example.com/repo:tag \
  --image-digest sha256:<digest>

# Augment SBOMs for all images in a snapshot
mobster augment --output sboms/ oci-image --snapshot snapshot.json

# Upload a single SBOM to Trusted Profile Analyzer
mobster upload tpa \
  --tpa-base-url https://your-tpa-instance.com \
  --file sbom.json

# See all available commands and options
mobster --help
mobster generate --help
```

## Context within Konflux

Mobster is a tool used for creating both Build-time and Release-time SBOMs.

- Build-time SBOM creation is invoked in `konflux-ci/build-definitions`
  repository. 
- Release-time SBOM creation is invoked through tekton tasks (in the `tasks/`
  dir) that are distributed to and used in `konflux-ci/release-service-catalog`
  repository.
- Build-time SBOMs can be contextualized. For builder-content
  contextualization, Mobster requires metadata output from `konflux-ci/capo`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for environment setup, running checks, and submitting a pull request.

## Resources

- [Development environment](docs/development-environment.md)
- [Release process](docs/release.md)
- [Full documentation](https://konflux-ci.dev/mobster/)
- [License](https://github.com/konflux-ci/mobster/blob/main/LICENSE) — Apache License 2.0
