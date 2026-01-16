import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.image import Image
from tests.spdx_builder import AnnotatedPackage, SPDXPackageBuilder, SPDXSBOMBuilder


@dataclass
class GenerateData:
    """
    Dataclass collecting input arguments for a 'mobster generate oci-image'
    call.
    """

    image: Image
    output_sbom_path: Path
    input_sbom_path: Path | None = None
    df_json_path: Path | None = None
    base_images_path: Path | None = None
    contextualize: bool = True


def run_mobster_generate(gdata: GenerateData) -> None:
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

    if gdata.base_images_path:
        cmd.extend(
            [
                "--base-image-digest-file",
                str(gdata.base_images_path),
            ]
        )

    if gdata.df_json_path:
        cmd.extend(["--parsed-dockerfile-path", str(gdata.df_json_path)])

    subprocess.run(cmd, check=True)


@pytest.fixture
def grandparent_packages() -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be specific to the
    grandparent after parent/component contextualization.
    """
    return [
        SPDXPackageBuilder()
        .name("github.com/gin-gonic/gin")
        .version("v1.9.1")
        .sha256_checksum(
            "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
        )
        .purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1")
        .build()
    ]


@pytest.fixture
def parent_packages() -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be specific to the parent
    after component contextualization.

    Tests multiple purl matching mechanisms.
    """
    checksum_match = (
        SPDXPackageBuilder()
        .name("golang.org/x/crypto")
        .version("v0.14.0")
        .sha256_checksum(
            "9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .purl("pkg:golang/golang/golang.org/x/crypto@v0.14.0")
        .build()
    )

    verification_code_match = (
        SPDXPackageBuilder()
        .name("golang.org/x/random")
        .version("v0.14.0")
        .purl("pkg:golang/golang/golang.org/x/random@v0.14.0")
        .verification_code("d6a770ba38583ed4bb4525bd96e50461655d2758")
        .build()
    )

    purl_match = (
        SPDXPackageBuilder()
        .name("golang.org/x/malware")
        .version("v1.14.0")
        .purl("pkg:golang/golang/golang.org/x/malware@v1.14.0")
        .build()
    )

    return [
        checksum_match,
        verification_code_match,
        purl_match,
    ]


@pytest.fixture
def parent_only_packages() -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be removed from the
    component SBOM after contextualization. This simulates a case when some
    packages are remove during a component build.
    """
    return [
        SPDXPackageBuilder()
        .name("golang.org/x/ginkgo")
        .version("v0.14.0")
        .sha256_checksum(
            "487198278acdcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .purl("pkg:golang/golang/golang.org/x/ginkgo@v0.14.0")
        .build()
    ]


@pytest.fixture
def component_packages() -> list[AnnotatedPackage]:
    """
    Returns a list of annotated packages that should be specific to the
    component SBOM after contextualization.
    """
    return [
        SPDXPackageBuilder()
        .name("golang.org/x/stdlib")
        .version("v0.14.0")
        .sha256_checksum(
            "1237773276cdcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .purl("pkg:golang/golang/golang.org/x/stdlib@v0.14.0")
        .build()
    ]


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
    spdx_id: str, relationships: list[Relationship], packages: list[AnnotatedPackage]
) -> None:
    """
    Verify that the passed packages have relationships that point to the
    specified spdx_id (spdx_id CONTAINS package.spdx_id).
    """
    package_set = {apkg.spdx_id for apkg in packages}
    for apkg in packages:
        for rel in relationships:
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


@pytest.fixture
def make_parsed_dockerfile_json(tmp_path: Path) -> Any:
    """
    Factory fixture that returns a function that can generate a parsed
    dockerfile json from an image, simulating an ancestor relationship.
    """

    def _make_parsed_dockerfile_json(img: Image) -> Path:
        parsed_df = {
            "Stages": [
                {
                    "BaseName": f"{img.repository}:{img.tag}",
                    "From": {"Image": f"{img.repository}:{img.tag}"},
                },
            ]
        }

        path = tmp_path / f"{img.digest}.df.json"
        with open(path, "w") as fp:
            fp.write(json.dumps(parsed_df))
        return path

    return _make_parsed_dockerfile_json


@pytest.fixture
def make_base_images_digests(tmp_path: Path) -> Any:
    """
    Factory fixture that returns a function that can generate a
    base-images-digests file from an image, simulating an ancestor
    relationship.
    """

    def _make_base_images_digests(img: Image) -> Path:
        path = tmp_path / f"{img.digest}.base_images.txt"
        with open(path, "w") as fp:
            fp.write(
                f"{img.repository}:{img.tag} {img.repository}:{img.tag}@{img.digest}\n"
            )
        return path

    return _make_base_images_digests


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
