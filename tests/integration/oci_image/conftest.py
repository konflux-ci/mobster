import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.cmd.generate.oci_image.contextual_sbom.builder import (
    BuilderPkgMetadataItem,
)
from mobster.image import Image
from tests.spdx_builder import AnnotatedPackage, SPDXPackageBuilder, SPDXSBOMBuilder


@dataclass
class SBOMPackage:
    """Interchange format for a (non-image) package in an SBOM.

    Since our tests sometimes need the same package data in AnnotatedPackage
    and BuilderPkgMetadataItem formats, we use this class as to avoid declaring
    the same strings twice.

    This does not support generating AnnotatedPackages for OCI images."""

    name: str
    purl: str
    version: str
    dependency_of_purl: str | None
    sha256_checksum: str | None
    verification_code: str | None

    def to_spdx(self) -> AnnotatedPackage:
        """Convert to AnnotatedPackage (using SPDXPackageBuilder).

        The verification_code and sha256_checksum fields will be added if
        available."""
        builder = (
            SPDXPackageBuilder().name(self.name).purl(self.purl).version(self.version)
        )
        if self.sha256_checksum:
            builder.sha256_checksum(self.sha256_checksum)
        if self.verification_code:
            builder.verification_code(self.verification_code)
        return builder.build()

    def to_metadata(
        self, origin_type: Literal["builder", "intermediate"], origin_pullspec: str
    ) -> BuilderPkgMetadataItem:
        """Convert to BuilderPkgMetadataItem.

        Ignores verification_code as it is not a valid field for this format
        currently."""
        item = BuilderPkgMetadataItem(
            purl=self.purl,
            dependency_of_purl=self.dependency_of_purl,
            pullspec=origin_pullspec,
            origin_type=origin_type,
        )
        if self.sha256_checksum:
            item.checksums = [f"sha256:{self.sha256_checksum}"]
        return item


@pytest.fixture
def gin_pkg() -> SBOMPackage:
    return SBOMPackage(
        name="github.com/gin-gonic/gin",
        version="v1.9.1",
        purl="pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        dependency_of_purl=None,
        sha256_checksum="a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
        verification_code=None,
    )


@pytest.fixture
def crypto_pkg() -> SBOMPackage:
    return SBOMPackage(
        name="golang.org/x/crypto",
        version="v0.14.0",
        purl="pkg:golang/golang.org/x/crypto@v0.14.0",
        dependency_of_purl=None,
        sha256_checksum="9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        verification_code=None,
    )


@pytest.fixture
def random_pkg() -> SBOMPackage:
    return SBOMPackage(
        name="golang.org/x/random",
        version="v0.14.0",
        purl="pkg:golang/golang.org/x/random@v0.14.0",
        dependency_of_purl=None,
        sha256_checksum=None,
        verification_code="d6a770ba38583ed4bb4525bd96e50461655d2758",
    )


@pytest.fixture
def malware_pkg() -> SBOMPackage:
    return SBOMPackage(
        name="golang.org/x/malware",
        version="v1.14.0",
        purl="pkg:golang/golang.org/x/malware@v1.14.0",
        dependency_of_purl="pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        sha256_checksum=None,
        verification_code=None,
    )


@pytest.fixture
def ginkgo_pkg() -> SBOMPackage:
    return SBOMPackage(
        name="golang.org/x/ginkgo",
        version="v0.14.0",
        purl="pkg:golang/golang.org/x/ginkgo@v0.14.0",
        dependency_of_purl=None,
        sha256_checksum="487198278acdcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        verification_code=None,
    )


@pytest.fixture
def stdlib_pkg() -> SBOMPackage:
    return SBOMPackage(
        name="golang.org/x/stdlib",
        version="v0.14.0",
        purl="pkg:golang/golang.org/x/stdlib@v0.14.0",
        dependency_of_purl=None,
        sha256_checksum="1237773276cdcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        verification_code=None,
    )


@dataclass
class GenerateData:
    """
    Dataclass collecting input arguments for a 'mobster generate oci-image'
    call.
    """

    output_sbom_path: Path
    image: Image | None = None
    input_sbom_path: Path | None = None
    metadata_path: Path | None = None
    build_metadata_path: Path | None = None
    contextualize: bool = True


def run_mobster_generate(gdata: GenerateData) -> subprocess.CompletedProcess[bytes]:
    """
    Run a mobster generate oci image command with the supplied arguments.
    """
    cmd = ["mobster", "generate", "--output", str(gdata.output_sbom_path), "oci-image"]
    if gdata.input_sbom_path is not None:
        cmd.extend(
            [
                "--from-syft",
                str(gdata.input_sbom_path),
            ]
        )
    if gdata.image is not None and gdata.image.digest is not None:
        cmd.extend(
            [
                "--image-digest",
                gdata.image.digest,
            ]
        )
    if gdata.image is not None and gdata.image.repository is not None:
        cmd.extend(
            [
                "--image-pullspec",
                f"{gdata.image.repository}:{gdata.image.tag}",
            ]
        )

    if gdata.contextualize:
        cmd.append("--contextualize")

    if gdata.metadata_path:
        cmd.extend(["--metadata-path", str(gdata.metadata_path)])

    if gdata.build_metadata_path:
        cmd.extend(["--build-metadata-path", str(gdata.build_metadata_path)])

    return subprocess.run(cmd, check=True, capture_output=True)


@pytest.fixture
def grandparent_packages(gin_pkg: SBOMPackage) -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be specific to the
    grandparent after parent/component contextualization.
    """
    return [gin_pkg.to_spdx()]


@pytest.fixture
def parent_packages(
    crypto_pkg: SBOMPackage,
    random_pkg: SBOMPackage,
    malware_pkg: SBOMPackage,
) -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be specific to the parent
    after component contextualization.

    Tests multiple purl matching mechanisms.
    """
    checksum_match = crypto_pkg.to_spdx()

    verification_code_match = random_pkg.to_spdx()

    purl_match = malware_pkg.to_spdx()

    return [
        checksum_match,
        verification_code_match,
        purl_match,
    ]


@pytest.fixture
def parent_only_packages(ginkgo_pkg: SBOMPackage) -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be removed from the
    component SBOM after contextualization. This simulates a case when some
    packages are remove during a component build.
    """
    return [ginkgo_pkg.to_spdx()]


@pytest.fixture
def component_packages(stdlib_pkg: SBOMPackage) -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be specific to the
    component SBOM after contextualization.
    """
    return [stdlib_pkg.to_spdx()]


@pytest.fixture
def grandparent_input_sbom(
    tmp_path: Path, grandparent_packages: list[AnnotatedPackage]
) -> Path:
    """
    Returns a path to an "input sbom" (syft SBOM imitation) to run mobster
    generate on.
    """
    doc = (
        SPDXSBOMBuilder()
        .name("grandparent")
        .root_contains(grandparent_packages)
        .root_purl(
            "pkg:oci/registry.redhat.io%2Fubi10"
            "@sha256%3A4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43?arch=amd64"
        )
        .build()
    )

    path = tmp_path / "grandparent.input.spdx.json"
    write_file(doc, str(path))
    return path


@pytest.fixture
def grandparent_input_sbom_deep(
    tmp_path: Path, grandparent_packages: list[AnnotatedPackage]
) -> Path:
    """
    Returns a path to an "input sbom" (syft SBOM imitation) to run mobster
    generate on. This SBOM is "deep", i.e. the grandparent itself is a
    descendant of another image (represented by legacy BUILD_TOOL_OF
    relationship).
    """
    ancestor_package = (
        SPDXPackageBuilder()
        .name("grandgrandparent")
        .purl(
            "pkg:oci/ubi@sha256:4495380286c97b9c2635b0b5d6f227bbd9003628be8383a37ff99984eefa42ed"
            "?repository_url=registry.access.redhat.com/ubi9/ubi"
        )
        .spdx_id(
            "SPDXRef-image-registry.access.redhat.com-ubi9-"
            "ubi-a1e7b50818a33092b66efa581deba4379d0ae744749e9082e58a24f042e5f9fa"
        )
        .version(
            "sha256:4495380286c97b9c2635b0b5d6f227bbd9003628be8383a37ff99984eefa42ed"
        )
        .is_base_image_annotation()
        .build()
    )

    doc = (
        SPDXSBOMBuilder()
        .name("grandparent")
        .root_contains(grandparent_packages)
        .root_build_tool_of([ancestor_package])
        .root_purl(
            "pkg:oci/registry.redhat.io%2Fubi10"
            "@sha256%3A4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43?arch=amd64"
        )
        .build()
    )

    path = tmp_path / "grandparent.input.deep.spdx.json"
    write_file(doc, str(path))
    return path


@pytest.fixture
def parent_input_sbom(
    tmp_path: Path,
    grandparent_packages: list[AnnotatedPackage],
    parent_packages: list[AnnotatedPackage],
    parent_only_packages: list[AnnotatedPackage],
) -> Path:
    """
    Returns a path to an "input sbom" (syft SBOM imitation) to run mobster
    generate on.
    """
    doc = (
        SPDXSBOMBuilder()
        .name("parent")
        .root_contains(grandparent_packages)
        .root_contains(parent_packages)
        .root_contains(parent_only_packages)
        .root_purl(
            "pkg:oci/registry.redhat.io%2Fubi10"
            "@sha256%3A4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43?arch=amd64"
        )
        .build()
    )

    path = tmp_path / "parent.input.spdx.json"
    write_file(doc, str(path))
    return path


@pytest.fixture
def component_input_sbom(
    tmp_path: Path,
    grandparent_packages: list[AnnotatedPackage],
    parent_packages: list[AnnotatedPackage],
    component_packages: list[AnnotatedPackage],
) -> Path:
    """
    Returns a path to an "input sbom" (syft SBOM imitation) to run mobster
    generate on.
    """
    doc = (
        SPDXSBOMBuilder()
        .name("component")
        .root_contains(grandparent_packages)
        .root_contains(parent_packages)
        .root_contains(component_packages)
        .root_purl(
            "pkg:oci/registry.redhat.io%2Fubi10"
            "@sha256%3A4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43?arch=amd64"
        )
        .build()
    )

    path = tmp_path / "component.input.spdx.json"
    write_file(doc, str(path))
    return path


@pytest.fixture
def legacy_parent_sbom(
    tmp_path: Path,
    grandparent_packages: list[AnnotatedPackage],
    parent_packages: list[AnnotatedPackage],
    parent_only_packages: list[AnnotatedPackage],
) -> Path:
    """
    Returns a path to an "input sbom" (syft SBOM imitation) to run mobster
    generate on. This parent SBOM imitates a legacy parent SBOM - it only uses
    BUILD_TOOL_OF relationships.
    """
    base_img_package: AnnotatedPackage = (
        SPDXPackageBuilder()
        .name("grandparent-base-img")
        .purl(
            "pkg:oci/ubi@sha256:4495380286c97b9c2635b0b5d6f227bbd9003628be8383a37ff99984eefa42ed"
            "?repository_url=registry.access.redhat.com/ubi9/ubi"
        )
        .is_base_image_annotation()
        .spdx_id(
            "SPDXRef-image-registry.access.redhat.com-ubi9-"
            "ubi-a1e7b50818a33092b66efa581deba4379d0ae744749e9082e58a24f042e5f9fa"
        )
        .version(
            "sha256:4495380286c97b9c2635b0b5d6f227bbd9003628be8383a37ff99984eefa42ed"
        )
        .build()
    )
    builder_package: AnnotatedPackage = (
        SPDXPackageBuilder()
        .name("parent-builder")
        .purl(
            "pkg:oci/ubi@sha256:881aaf5fa0d1f85925a1b9668a1fc7f850a11ca30fd3e37ea194db4edff892a5"
            "?repository_url=registry.access.redhat.com/ubi8/ubi"
        )
        .spdx_id(
            "SPDXRef-image-registry.access.redhat.com-ubi8-ubi-"
            "f39187f0b9f80f85f8e55044607742e71ea7d62a5c27edad17cb7c70f6e06e50"
        )
        .version("881aaf5fa0d1f85925a1b9668a1fc7f850a11ca30fd3e37ea194db4edff892a5")
        .is_builder_image_for_stage_annotation(0)
        .build()
    )

    doc = (
        SPDXSBOMBuilder()
        .name("parent")
        .root_contains(grandparent_packages)
        .root_contains(parent_packages)
        .root_contains(parent_only_packages)
        .root_build_tool_of([base_img_package] + [builder_package])
        .root_purl(
            "pkg:oci/registry.redhat.io%2Fubi10"
            "@sha256%3A4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43?arch=amd64"
        )
        .build()
    )

    path = tmp_path / "parent.input.spdx.json"
    write_file(doc, str(path))
    return path


def verify_relationship(
    relationships: list[Relationship],
    spdx_id: str,
    relationship_type: RelationshipType,
    related_spdx_id: str,
):
    """Verify that a list of relationships contains a specific relationship."""
    matches = []
    for rel in relationships:
        # match the 3 relational fields
        if rel.spdx_element_id != spdx_id:
            continue
        if rel.relationship_type != relationship_type:
            continue
        if rel.related_spdx_element_id != related_spdx_id:
            continue
        # if so we add it here
        matches.append(rel)
    assert len(matches) > 0, (
        f"{spdx_id} does not have expected "
        f"{rel.relationship_type} relationship to {related_spdx_id}"
    )
    # sanity check - unlikely this will happen, but just to be sure:
    assert len(matches) < 2, (
        f"{spdx_id} has duplicate "
        f"{rel.relationship_type} relationship to {related_spdx_id}"
    )


def verify_sbom_relationships(
    sbom_path: Path, package_groups: list[list[AnnotatedPackage]]
) -> None:
    """
    Verify SBOM relationships using dependency chain order.

    Args:
        sbom_path: Path to an SBOM document to verify
        package_groups: List of package lists in component-first order
                       [component_packages, parent_packages, grandparent_packages, ...]
    """
    sbom_doc = parse_file(str(sbom_path))
    dep_chain = get_dependency_chain_spdx_ids(sbom_doc.relationships)
    assert len(dep_chain) == len(package_groups), (
        f"Invalid number of dependents. Dependency chain: {dep_chain}"
    )

    for spdx_id, packages in zip(dep_chain, package_groups, strict=False):
        verify_relationships(spdx_id, sbom_doc.relationships, packages)


def verify_relationships(
    spdx_id: str,
    relationships: list[Relationship],
    packages: list[AnnotatedPackage],
    relationship_type: RelationshipType | None = None,
) -> None:
    """
    Verify that the passed packages have relationships that point to the
    specified spdx_id (e.g. spdx_id CONTAINS package.spdx_id)
    Can also be filtered to verify only a specific relationship, e.g. BUILD_TOOL_OF.
    """
    package_set = {apkg.spdx_id for apkg in packages}
    for apkg in packages:
        for rel in relationships:
            # skip any relationship that isn't of the specified
            # relationship_type, if applicable
            if (
                relationship_type is not None
                and rel.relationship_type != relationship_type
            ):
                continue
            if rel.related_spdx_element_id != apkg.spdx_id:
                continue

            assert rel.spdx_element_id == spdx_id, (
                f"Relationship of the package with spdx id {apkg.spdx_id} "
                "points to wrong spdx id."
            )
            package_set.remove(apkg.spdx_id)

    assert len(package_set) == 0, (
        f"SPDX IDs of packages that were not found: {package_set}"
    )


def verify_packages_not_included(
    sbom_path: Path, excluded: list[AnnotatedPackage]
) -> None:
    """
    Verify that the passed packages are not found in the specified SBOM
    document (by spdx_id).
    """
    sbom_doc = parse_file(str(sbom_path))
    excluded_spdx_ids = {apkg.spdx_id for apkg in excluded}

    for pkg in sbom_doc.packages:
        assert pkg.spdx_id not in excluded_spdx_ids, (
            "The SBOM document contains a package that must be excluded."
        )


def get_dependency_chain_spdx_ids(relationships: list[Relationship]) -> list[str]:
    """
    Using the provided relationships, builds a dependency chain based on the
    DESCENDANT_OF relationships. The root element is the first element in the
    list. Fails if there are multiple roots or if a dependency tree is deteced.
    """
    rels = [
        rel
        for rel in relationships
        if rel.relationship_type == RelationshipType.DESCENDANT_OF
    ]

    parents, children = set(), set()
    for rel in rels:
        parents.add(rel.spdx_element_id)
        children.add(str(rel.related_spdx_element_id))

    # the root element is the one that is never a child in any relationship
    no_children = parents - children
    root = no_children.pop()
    assert len(no_children) == 0, "Found multiple roots in SBOM relationships."

    parent_to_child = {}
    for rel in rels:
        assert rel.spdx_element_id not in parent_to_child, (
            "Detected a dependency tree in relationships instead of a path."
        )
        parent_to_child[rel.spdx_element_id] = str(rel.related_spdx_element_id)

    # build chain starting from root
    spdx_ids = [root]
    current = root
    while current in parent_to_child:
        current = parent_to_child[current]
        spdx_ids.append(current)

    return spdx_ids
