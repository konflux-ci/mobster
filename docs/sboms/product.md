# Product SBOM generation

Mobster supports generating so-called "Product SBOMs" that allow linking the
Konflux components being released with a Red Hat product.

```sh
$ mobster generate product \
    --release-data data.json \
    --snapshot snapshot.json > product.json
```

## Example generation
Here is an example of a release data json document:
```json
{
  "releaseNotes": {
    "productName": "Product",
    "productVersion": "1.0",
    "cpe": [
      "cpe:/a:redhat:product:1.0::el9",
      "cpe:/a:redhat:product:1.0::el10",
    ]
  }
}
```

Now we need a mapped snapshot spec file to pair the SBOM with the released
components:
```json
{
  "components": [
    {
      "name": "mobster-demo",
      "containerImage": "quay.io/redhat-prod/mobster-demo@sha256:b26c754d32aa87cddc1f1ae8edefaf24cc137ca13c32a663ed082f665d3e49e8",
      "rh-registry-repo": "registry.redhat.io/mobster-demo",
      "repository": "quay.io/redhat-prod/mobster-demo",
      "tags": ["1.0", "latest"]
    }
  ]
}
```

After running the generate product command with the release data and the
snapshot, we get an SBOM that links the CPEs and product data in the release
data file with the components being released:
```json
{
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {
        "created": "2025-06-09T09:48:54Z",
        "creators": [
            "Organization: Red Hat",
            "Tool: Konflux CI",
            "Tool: Mobster-0.1.0"
        ]
    },
    "dataLicense": "CC0-1.0",
    "name": "Product-1.0",
    "spdxVersion": "SPDX-2.3",
    "documentNamespace": "https://konflux-ci.dev/spdxdocs/Product-1.0-3ae914a2-eb6d-44e0-a144-0b0bf49f5178",
    "packages": [
        {
            "SPDXID": "SPDXRef-product",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:product:1.0::el9",
                    "referenceType": "cpe22Type"
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceLocator": "cpe:/a:redhat:product:1.0::el10",
                    "referenceType": "cpe22Type"
                },
            ],
            "filesAnalyzed": false,
            "licenseDeclared": "NOASSERTION",
            "name": "Product",
            "supplier": "Organization: Red Hat",
            "versionInfo": "1.0"
        },
        {
            "SPDXID": "SPDXRef-mobster-demo",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": "b26c754d32aa87cddc1f1ae8edefaf24cc137ca13c32a663ed082f665d3e49e8"
                }
            ],
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceLocator": "pkg:oci/mobster-demo@sha256:b26c754d32aa87cddc1f1ae8edefaf24cc137ca13c32a663ed082f665d3e49e8?repository_url=registry.redhat.io/mobster-demo&tag=1.0",
                    "referenceType": "purl"
                },
                {
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceLocator": "pkg:oci/demo@sha256:b26c754d32aa87cddc1f1ae8edefaf24cc137ca13c32a663ed082f665d3e49e8?repository_url=registry.redhat.io/mobster-demo&tag=latest",
                    "referenceType": "purl"
                }
            ],
            "filesAnalyzed": false,
            "licenseDeclared": "NOASSERTION",
            "name": "demo",
            "supplier": "Organization: Red Hat"
        }
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": "SPDXRef-product",
            "relationshipType": "DESCRIBES"
        },
        {
            "spdxElementId": "SPDXRef-mobster-demo",
            "relatedSpdxElement": "SPDXRef-product",
            "relationshipType": "PACKAGE_OF"
        }
    ]
}
```

# Structure of the generated SBOM

The generated SBOM has following structure:
```
 - SPDXRef-DOCUMENT
    - SPDXRef-product (DESCRIBES)
        - Component XYZ (PACKAGE_OF)
        - Component ABC (PACKAGE_OF)
```
