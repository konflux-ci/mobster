# SBOM formats
SBOM documents can be represented in a variety of formats. Each format was designed
to address different use cases and requirements, but they all
aim to provide a comprehensive view of the software components and their relationships.

The most common formats are:

- [SPDX](https://spdx.dev/)
- [CycloneDX](https://cyclonedx.org/)

Mobster can generate SBOMs in both formats, allowing users to choose the one that best fits their needs.
However, the SPDX format is preferred by the Konflux project and Red Hat Product Security.

## SPDX
A standardized format for describing software licenses, copyright, and component metadata for compliance and security.

Mobster uses the official [spdx-tools Python library](https://pypi.org/project/spdx-tools/) to generate
SBOMs in the SPDX format and validate them.

A currently supported SPDX schema version is [2.3](https://spdx.github.io/spdx-spec/v2.3/).
## CycloneDX
A lightweight, security-focused BOM format for detailing components, dependencies, and vulnerabilities.

Mobster uses the official [cyclonedx-python-lib Python library](https://pypi.org/project/cyclonedx-python-lib/)
to generate SBOMs in the CycloneDX format and validate them.

A currently supported CycloneDX schema version is [1.6](https://cyclonedx.org/docs/1.6/json/).
