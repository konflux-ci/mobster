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
  guidelies](https://github.com/RedHatProductSecurity/security-data-guidelines/tree/main).
- **Distribution**: Distribute the SBOM document to various set of locations (e.g. Trusted
  Profile Analyzer, container registry, etc.)

## Getting started

To use the Mobster tool, you need to install it first. There are multiple ways to isnstall
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

## Development environment

Follow an instruction in the [development-environment.md](docs/development-environment.md)
file to set up your development environment.


## Contributing
We welcome contributions to the Mobster project! If you would like to contribute, please follow these steps:
1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes and commit them with a clear message (following the
   [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/) format)
   (e.g. `feat: add new feature` or `fix: fix a bug`)
4. Open a pull request to the main repository
5. Make sure the CI checks pass and the code is properly formatted
6. Wait for the review and address any comments or suggestions
7. Once your changes are approved, they will be merged into the main branch
8. Congratulations! You have successfully contributed to the Mobster project

## Release process
The release process is automated using GitHub Actions and Konflux. The process
is described in detail in the [release.md](docs/release.md) file.

## Documentation
The documentation for the Mobster project is available in the [docs](/docs/) directory.

## License
This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
