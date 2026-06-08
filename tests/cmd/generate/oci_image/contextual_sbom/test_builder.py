import json
import logging

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.relationship import RelationshipType

from mobster.cmd.generate.oci_image.contextual_sbom.builder import (
    BuilderContextualizer,
    BuilderPkgMetadata,
    BuilderPkgMetadataItem,
    Origin,
)
from mobster.cmd.generate.oci_image.contextual_sbom.constants import OriginType
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
        .is_builder_image_for_stage_annotation(0)
        .build()
    )

    syft_img_pkg = (
        SPDXPackageBuilder()
        .name("syft")
        .version(syft_version)
        .purl(f"pkg:oci/{syft_name}@{syft_version}?repository_url={syft_repo}")
        .spdx_id("SPDXRef-image-syft-1234")
        .is_builder_image_for_stage_annotation(1)
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


@pytest.fixture
def metadata_two_images() -> BuilderPkgMetadata:
    return BuilderPkgMetadata(
        packages=[
            BuilderPkgMetadataItem(
                purl="pkg:golang/dario.cat/mergo@v1.0.1",
                origin_type=OriginType("builder"),
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/stdlib@v1.0.0",
                origin_type=OriginType("intermediate"),
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/syft@v1.0.1",
                origin_type=OriginType("builder"),
                pullspec="quay.io/konflux-ci/syft@sha256:bbbb",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/math@v1.0.0",
                origin_type=OriginType("builder"),
                pullspec="quay.io/konflux-ci/syft@sha256:bbbb",
                dependency_of_purl="pkg:golang/syft@v1.0.1",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/math@v1.0.0",
                origin_type=OriginType("builder"),
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
                dependency_of_purl="pkg:golang/dario.cat/mergo@v1.0.1",
            ),
        ]
    )


def test_generate_origins(
    sbom_index_two_images: DocumentIndexOCI, metadata_two_images: BuilderPkgMetadata
) -> None:
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

    assert (
        BuilderContextualizer().generate_origins(
            sbom_index_two_images, metadata_two_images
        )
        == expected_origins
    )


def test_generate_origins_without_metadata(
    sbom_index_two_images: DocumentIndexOCI,
) -> None:
    """
    Test case where there are no packages in the SBOM document without their
    respective metadata items.
    """
    metadata = BuilderPkgMetadata(packages=[])
    assert (
        BuilderContextualizer().generate_origins(sbom_index_two_images, metadata) == []
    )


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
                origin_type=OriginType("builder"),
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
        ]
    )
    assert (
        BuilderContextualizer().generate_origins(sbom_index_two_images, metadata) == []
    )


def test_resolve_origins(sbom_index_two_images: DocumentIndexOCI) -> None:
    origins = [
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

    # mapping of image package spdx ids to the package spdx ids that it has a
    # CONTAINS relationship with
    expected_package_attribution = {
        "SPDXRef-image-oras-1234-intermediate": {
            "SPDXRef-Package-stdlib-from-oras",
        },
        "SPDXRef-image-oras-1234": {
            "SPDXRef-Package-mergo-from-oras",
            "SPDXRef-Package-math-from-oras",
        },
        "SPDXRef-image-syft-1234": {
            "SPDXRef-Package-math-from-syft",
            "SPDXRef-Package-syft-from-syft",
        },
    }

    resolved = BuilderContextualizer().resolve_origins(sbom_index_two_images, origins)

    for (
        image_spdx_id,
        expected_contains_spdx_ids,
    ) in expected_package_attribution.items():
        image_pkg = resolved.package_by_spdx_id(image_spdx_id)

        contains_spdx_ids: set[str] = {
            rel.related_spdx_element_id  # type: ignore
            for rel in image_pkg.filter_parent_relationships(RelationshipType.CONTAINS)
        }

        assert expected_contains_spdx_ids.issubset(contains_spdx_ids)


def _contextualize_sbom_index() -> DocumentIndexOCI:
    """Two-images SBOM extended with packages that trigger skip-path logging."""
    oras_img_pkg = (
        SPDXPackageBuilder()
        .name("oras")
        .version("sha256:aaaa")
        .purl("pkg:oci/oras@sha256:aaaa?repository_url=quay.io/konflux-ci/oras")
        .spdx_id("SPDXRef-image-oras-1234")
        .is_builder_image_for_stage_annotation(0)
        .build()
    )
    syft_img_pkg = (
        SPDXPackageBuilder()
        .name("syft")
        .version("sha256:bbbb")
        .purl("pkg:oci/syft@sha256:bbbb?repository_url=quay.io/konflux-ci/syft")
        .spdx_id("SPDXRef-image-syft-1234")
        .is_builder_image_for_stage_annotation(1)
        .build()
    )
    mergo_pkg = (
        SPDXPackageBuilder()
        .name("pkg1")
        .spdx_id("SPDXRef-Package-mergo-from-oras")
        .version("1.0.0")
        .purl("pkg:golang/dario.cat/mergo@v1.0.1")
        .build()
    )
    syft_pkg = (
        SPDXPackageBuilder()
        .name("syft")
        .spdx_id("SPDXRef-Package-syft-from-syft")
        .version("1.0.0")
        .purl("pkg:golang/syft@v1.0.1")
        .build()
    )
    stdlib_pkg = (
        SPDXPackageBuilder()
        .name("pkg2")
        .spdx_id("SPDXRef-Package-stdlib-from-oras")
        .version("1.0.0")
        .purl("pkg:golang/stdlib@v1.0.0")
        .build()
    )
    math_from_oras = (
        SPDXPackageBuilder()
        .name("same_purl_pkg_1")
        .spdx_id("SPDXRef-Package-math-from-oras")
        .version("1.0.0")
        .purl("pkg:golang/math@v1.0.0")
        .build()
    )
    math_from_syft = (
        SPDXPackageBuilder()
        .name("same_purl_pkg_2")
        .spdx_id("SPDXRef-Package-math-from-syft")
        .version("1.0.0")
        .purl("pkg:golang/math@v1.0.0")
        .build()
    )
    math_without_dep = (
        SPDXPackageBuilder()
        .name("math_without_dep")
        .spdx_id("SPDXRef-Package-math-without-dep")
        .version("1.0.0")
        .purl("pkg:golang/math@v1.0.0")
        .build()
    )
    parent_without_purl = (
        SPDXPackageBuilder()
        .name("parent_without_purl")
        .spdx_id("SPDXRef-Package-parent-no-purl")
        .version("1.0.0")
        .build()
    )
    shared_dep_a = (
        SPDXPackageBuilder()
        .name("shared_dep_a")
        .spdx_id("SPDXRef-Package-shared-a")
        .version("1.0.0")
        .purl("pkg:golang/shared-dep@v1.0.0")
        .build()
    )
    shared_dep_b = (
        SPDXPackageBuilder()
        .name("shared_dep_b")
        .spdx_id("SPDXRef-Package-shared-b")
        .version("1.0.0")
        .purl("pkg:golang/shared-dep@v1.0.0")
        .build()
    )
    opt_bar_pkg = (
        SPDXPackageBuilder()
        .name("opt-bar")
        .spdx_id("SPDXRef-Package-opt-bar")
        .version("1.0.0")
        .purl("pkg:generic/opt-bar@1.0.0")
        .build()
    )

    document = (
        SPDXSBOMBuilder()
        .name("testing-doc")
        .root_purl("pkg:oci/image@sha256:deadbeef")
        .root_describes([oras_img_pkg, syft_img_pkg])
        .contains(oras_img_pkg, mergo_pkg)
        .contains(oras_img_pkg, opt_bar_pkg)
        .contains(oras_img_pkg, stdlib_pkg)
        .contains(oras_img_pkg, math_from_oras)
        .contains(oras_img_pkg, math_without_dep)
        .contains(oras_img_pkg, parent_without_purl)
        .contains(oras_img_pkg, shared_dep_a)
        .contains(oras_img_pkg, shared_dep_b)
        .contains(syft_img_pkg, syft_pkg)
        .contains(syft_img_pkg, math_from_syft)
        .dependency_of(math_from_oras, mergo_pkg)
        .dependency_of(math_from_syft, syft_pkg)
        .dependency_of(shared_dep_a, parent_without_purl)
        .dependency_of(shared_dep_b, mergo_pkg)
    ).build()

    return DocumentIndexOCI(document)


def _contextualize_metadata(
    metadata_two_images: BuilderPkgMetadata,
) -> BuilderPkgMetadata:
    return BuilderPkgMetadata(
        packages=[
            *metadata_two_images.packages,
            BuilderPkgMetadataItem(
                purl="pkg:golang/net@v1.0.1",
                origin_type=OriginType.BUILDER,
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/math@v1.0.0",
                origin_type=OriginType.BUILDER,
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/math@v1.0.0",
                origin_type=OriginType.BUILDER,
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
                dependency_of_purl="pkg:golang/nonexistent@v9.9.9",
            ),
            BuilderPkgMetadataItem(
                purl="pkg:golang/shared-dep@v1.0.0",
                origin_type=OriginType.BUILDER,
                pullspec="quay.io/konflux-ci/oras@sha256:aaaa",
                dependency_of_purl="pkg:golang/parent-expected@v1.0.0",
            ),
        ]
    )


def test_contextualize(
    metadata_two_images: BuilderPkgMetadata,
    caplog: LogCaptureFixture,
) -> None:
    index = _contextualize_sbom_index()
    metadata = _contextualize_metadata(metadata_two_images)
    contextualizer = BuilderContextualizer()

    with caplog.at_level(logging.INFO):
        document = contextualizer.contextualize(index, metadata)

    assert document is index.doc
    assert contextualizer.stats.total_metadata == len(metadata.packages)
    assert contextualizer.stats.purl_mismatch == 1
    assert contextualizer.stats.missed_ambiguous_purls_match == 1
    assert contextualizer.stats.faulty_dependency_of == 2
    assert contextualizer.stats.package_is_not_dependency == 2
    assert contextualizer.stats.dependent_has_no_purl == 1

    builder_log_messages = [
        record.message
        for record in caplog.records
        if record.name == "mobster.cmd.generate.oci_image.contextual_sbom.builder"
    ]
    assert (
        "PURLs in generated SBOM do not match PURL from metadata: pkg:golang/net@v1.0.1"
    ) in builder_log_messages
    assert (
        "Ambiguous PURL 'pkg:golang/math@v1.0.0' describes multiple packages "
        "and does not have DEPENDENCY_OF relationship!"
    ) in builder_log_messages
    assert (
        "Ambiguous PURL 'pkg:golang/math@v1.0.0' describes multiple packages "
        "and DEPENDENCY_OF relationship (pkg:golang/nonexistent@v9.9.9) "
        "could not be resolved!"
    ) in builder_log_messages
    assert (
        "Parent package with ID 'SPDXRef-Package-parent-no-purl' has no PURL"
    ) in builder_log_messages
    assert (
        "Ambiguous PURL 'pkg:golang/shared-dep@v1.0.0' describes multiple "
        "packages and DEPENDENCY_OF relationship "
        "(pkg:golang/parent-expected@v1.0.0) could not be resolved!"
    ) in builder_log_messages
    assert (
        builder_log_messages.count(
            "Package 'SPDXRef-Package-math-without-dep' has no relationships"
            " where it is dependency of anything!"
        )
        == 2
    )

    summary_records = [
        record
        for record in caplog.records
        if record.name == "mobster.cmd.generate.oci_image.contextual_sbom.logging"
    ]
    assert len(summary_records) == 1

    log_data = json.loads(summary_records[0].message)
    per_builder_by_id = {
        entry["builder_spdx_id"]: entry for entry in log_data["per_builder_stats"]
    }

    assert log_data["event_type"] == "contextual_sbom_builder_statistics"
    assert log_data["component_packages"] == {
        "total": len(metadata.packages),
        "purl_mismatch": 1,
        "faulty_dependency_of": 2,
        "package_is_not_dependency": 2,
        "dependent_has_no_purl": 1,
    }
    assert per_builder_by_id == {
        "SPDXRef-image-oras-1234": {
            "builder_spdx_id": "SPDXRef-image-oras-1234",
            "builder_purl": (
                "pkg:oci/oras@sha256:aaaa?repository_url=quay.io/konflux-ci/oras"
            ),
            "origins": {"builder": 2, "intermediate": 0, "external": 0},
        },
        "SPDXRef-image-oras-1234-intermediate": {
            "builder_spdx_id": "SPDXRef-image-oras-1234-intermediate",
            "builder_purl": "",
            "origins": {"builder": 0, "intermediate": 1, "external": 0},
        },
        "SPDXRef-image-syft-1234": {
            "builder_spdx_id": "SPDXRef-image-syft-1234",
            "builder_purl": (
                "pkg:oci/syft@sha256:bbbb?repository_url=quay.io/konflux-ci/syft"
            ),
            "origins": {"builder": 2, "intermediate": 0, "external": 0},
        },
    }
