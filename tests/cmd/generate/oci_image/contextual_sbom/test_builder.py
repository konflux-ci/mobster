import pytest

from mobster.cmd.generate.oci_image.contextual_sbom.builder import (
    BuilderPkgMetadata,
    BuilderPkgMetadataItem,
    Origin,
    OriginType,
    generate_origins,
)
from mobster.cmd.generate.oci_image.spdx_utils import DocumentIndexOCI
from tests.spdx_builder import SPDXPackageBuilder, SPDXSBOMBuilder


@pytest.fixture
def sbom_index_two_images() -> DocumentIndexOCI:
    """
    Fixture returning an index of an SBOM document for an OCI image with the
    following package layout:

    The SBOM root package describes two image packages:
        "SPDXRef-image-syft-1234" and "SPDXRef-image-oras-1234".

    The image package "SPDXRef-image-syft-1234" CONTAINS:
        - "SPDXRef-Package-syft-from-syft"
        - "SPDXRef-Package-math-from-syft" (Which is a DEPENDENCY_OF
            "SPDXRef-Package-syft-from-syft")

    The image package "SPDXRef-image-oras-1234" CONTAINS:
        - "SPDXRef-Package-mergo-from-oras"
        - "SPDXRef-Package-stdlib-from-oras"
        - "SPDXRef-Package-math-from-oras" (Which is a DEPENDENCY_OF
            "SPDXRef-Package-mergo-from-oras")
    """

    oras_name = "oras"
    oras_repo = f"quay.io/konflux-ci/{oras_name}"
    oras_version = "sha256:aaaa"

    syft_name = "syft"
    syft_repo = f"quay.io/konflux-ci/{syft_name}"
    syft_version = "sha256:bbbb"

    oras_img_pkg = (
        SPDXPackageBuilder()
        .name("oras")
        .version(oras_version)
        .purl(f"pkg:oci/{oras_name}@{oras_version}?repository_url={oras_repo}")
        .spdx_id("SPDXRef-image-oras-1234")
        .build()
    )

    syft_img_pkg = (
        SPDXPackageBuilder()
        .name("syft")
        .version(syft_version)
        .purl(f"pkg:oci/{syft_name}@{syft_version}?repository_url={syft_repo}")
        .spdx_id("SPDXRef-image-syft-1234")
        .build()
    )

    pkg_builder_1 = (
        SPDXPackageBuilder()
        .name("pkg1")
        .spdx_id("SPDXRef-Package-mergo-from-oras")
        .version("1.0.0")
        .purl("pkg:golang/dario.cat/mergo@v1.0.1")
        .build()
    )

    pkg_builder_2 = (
        SPDXPackageBuilder()
        .name("syft")
        .spdx_id("SPDXRef-Package-syft-from-syft")
        .version("1.0.0")
        .purl("pkg:golang/syft@v1.0.1")
        .build()
    )

    pkg_intermediate = (
        SPDXPackageBuilder()
        .name("pkg2")
        .spdx_id("SPDXRef-Package-stdlib-from-oras")
        .version("1.0.0")
        .purl("pkg:golang/stdlib@v1.0.0")
        .build()
    )

    same_purl_pkg_1 = (
        SPDXPackageBuilder()
        .name("same_purl_pkg_1")
        .spdx_id("SPDXRef-Package-math-from-oras")
        .version("1.0.0")
        .purl("pkg:golang/math@v1.0.0")
        .build()
    )

    same_purl_pkg_2 = (
        SPDXPackageBuilder()
        .name("same_purl_pkg_2")
        .spdx_id("SPDXRef-Package-math-from-syft")
        .version("1.0.0")
        .purl("pkg:golang/math@v1.0.0")
        .build()
    )

    document = (
        SPDXSBOMBuilder()
        .name("testing-doc")
        .root_purl("pkg:oci/image@sha256:deadbeef")
        .root_describes([oras_img_pkg, syft_img_pkg])
        .contains(oras_img_pkg, pkg_builder_1)
        .contains(oras_img_pkg, pkg_intermediate)
        .contains(oras_img_pkg, same_purl_pkg_1)
        .contains(syft_img_pkg, pkg_builder_2)
        .contains(syft_img_pkg, same_purl_pkg_2)
        .dependency_of(same_purl_pkg_1, pkg_builder_1)
        .dependency_of(same_purl_pkg_2, pkg_builder_2)
    ).build()

    index = DocumentIndexOCI(document)
    return index


def test_generate_origins(sbom_index_two_images: DocumentIndexOCI) -> None:
    metadata = BuilderPkgMetadata(
        packages=[
            BuilderPkgMetadataItem(
                purl="pkg:golang/dario.cat/mergo@v1.0.1",
                origin_type="builder",
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/stdlib@v1.0.0",
                origin_type="intermediate",
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/syft@v1.0.1",
                origin_type="builder",
                pullspec="quay.io/konflux-ci/syft@sha256:bbbb",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/math@v1.0.0",
                origin_type="builder",
                pullspec="quay.io/konflux-ci/syft@sha256:bbbb",
                dependency_of_purl="pkg:golang/syft@v1.0.1",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/math@v1.0.0",
                origin_type="builder",
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
                dependency_of_purl="pkg:golang/dario.cat/mergo@v1.0.1",
            ),
        ]
    )

    expected_origins = [
        (
            "SPDXRef-Package-mergo-from-oras",
            Origin(
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa", type=OriginType.BUILDER
            ),
        ),
        (
            "SPDXRef-Package-stdlib-from-oras",
            Origin(
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
                type=OriginType.INTERMEDIATE,
            ),
        ),
        (
            "SPDXRef-Package-syft-from-syft",
            Origin(
                pullspec="quay.io/konflux-ci/syft@sha256:bbbb", type=OriginType.BUILDER
            ),
        ),
        (
            "SPDXRef-Package-math-from-syft",
            Origin(
                pullspec="quay.io/konflux-ci/syft@sha256:bbbb", type=OriginType.BUILDER
            ),
        ),
        (
            "SPDXRef-Package-math-from-oras",
            Origin(
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa", type=OriginType.BUILDER
            ),
        ),
    ]

    assert generate_origins(sbom_index_two_images, metadata) == expected_origins


def test_generate_origins_without_metadata(
    sbom_index_two_images: DocumentIndexOCI,
) -> None:
    """
    Test case where there are no packages in the SBOM document without their
    respective metadata items.
    """
    metadata = BuilderPkgMetadata(packages=[])
    assert generate_origins(sbom_index_two_images, metadata) == []


def test_generate_origins_metadata_missing_package(
    sbom_index_two_images: DocumentIndexOCI,
) -> None:
    """
    Test case where there is a metadata item with no matching package in the
    SBOM document.
    """
    metadata = BuilderPkgMetadata(
        packages=[
            BuilderPkgMetadataItem(
                purl="pkg:golang/net@v1.0.1",
                origin_type="builder",
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
        ]
    )
    assert generate_origins(sbom_index_two_images, metadata) == []


# TODO: test dependency_of_purl resolution when the chain is deeper and there
# is some black magic fuckery
# Think of problems
