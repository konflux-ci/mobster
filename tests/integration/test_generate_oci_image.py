import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackagePurpose,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.image import Image
from tests.integration.oci_client import ReferrersTagOCIClient


@dataclass
class InputSBOM:
    """
    Dataclass representing a "syft" input SBOM to a 'mobster generate
    oci-image' call.
    """

    root_package_spdx_id: str
    document: Document


@dataclass
class GenerateData:
    """
    Dataclass representing input data to a 'mobster generate oci-image' call.
    """

    input_sbom_path: Path
    input_sbom: InputSBOM
    output_sbom_path: Path
    df_json_path: Path | None
    base_images_path: Path | None


@pytest.mark.asyncio
@pytest.mark.skip(reason="waiting for package matching implementation")
async def test_parent_content_contextualizaton(
    oci_client: ReferrersTagOCIClient, tmp_path: Path
) -> None:
    """
    Test the parent content contextualization in 'mobster generate oci-image' by
    generating three SBOMs (grandparent, parent, component). All three input
    SBOMs share some common packages, parent and component share some packages
    and some packages are component-only.

    This test verifies that after these three mobster calls, the final
    component SBOM has its package relationships updated to reflect the true
    origin of packages.
    """
    common_packages: list[Package] = _get_common_packages()
    parent_packages: list[Package] = _get_parent_packages()
    component_packages: list[Package] = _get_component_packages()

    grandparent_img = await _run_generate_grandparent(
        oci_client=oci_client, tmp_path=tmp_path, common_packages=common_packages
    )

    parent_img, parent_data = await _run_generate_parent(
        oci_client=oci_client,
        tmp_path=tmp_path,
        grandparent_img=grandparent_img,
        common_packages=common_packages,
        parent_packages=parent_packages,
    )

    _verify_parent_relationships_contextualized(
        parent_data.output_sbom_path, common_packages, parent_packages
    )

    (
        component_img,
        component_data,
    ) = await _run_generate_component(
        oci_client=oci_client,
        tmp_path=tmp_path,
        parent_img=parent_img,
        common_packages=common_packages,
        parent_packages=parent_packages,
        component_packages=component_packages,
    )

    _verify_component_relationships_contextualized(
        component_data.output_sbom_path,
        common_packages,
        parent_packages,
        component_packages,
    )


async def _run_generate_grandparent(
    *,
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    common_packages: list[Package],
) -> Image:
    """
    Setup and generate grandparent SBOM.
    """
    grandparent_data = _get_grandparent_gdata(tmp_path, common_packages)

    grandparent_img = await oci_client.create_image("grandparent", "latest")

    _run_mobster_generate(grandparent_img, grandparent_data)

    with open(grandparent_data.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(grandparent_img, "spdx", f.read())

    return grandparent_img


async def _run_generate_parent(
    *,
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    grandparent_img: Image,
    common_packages: list[Package],
    parent_packages: list[Package],
) -> tuple[Image, GenerateData]:
    """
    Setup and generate parent SBOM.
    """
    parent_data = _get_parent_gdata(
        tmp_path, grandparent_img, common_packages, parent_packages
    )

    parent_img = await oci_client.create_image("parent", "latest")

    _run_mobster_generate(parent_img, parent_data)

    with open(parent_data.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(parent_img, "spdx", f.read())

    return parent_img, parent_data


async def _run_generate_component(
    *,
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    parent_img: Image,
    common_packages: list[Package],
    parent_packages: list[Package],
    component_packages: list[Package],
) -> tuple[Image, GenerateData]:
    """
    Setup and generate component SBOM.
    """
    component_data = _get_component_gdata(
        tmp_path,
        parent_img,
        common_packages,
        parent_packages,
        component_packages,
    )
    component_img = await oci_client.create_image("component", "latest")

    _run_mobster_generate(component_img, component_data)

    return component_img, component_data


def _run_mobster_generate(img: Image, gdata: GenerateData) -> None:
    """
    Run a mobster generate oci image command for the image and its generate
    data.
    """
    cmd = [
        "mobster",
        "generate",
        "--output",
        str(gdata.output_sbom_path),
        "oci-image",
        "--from-syft",
        str(gdata.input_sbom_path),
        "--image-digest",
        img.digest,
        "--image-pullspec",
        f"{img.repository}:{img.tag}",
    ]

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


def _get_common_packages() -> list[Package]:
    """
    Get a list of packages that will be added both to the grandparent, parent
    and component SBOMs with a CONTAINS relationship. After contextualization,
    all of these packages in the final component SBOM should have the
    relationships pointing to the grandparent.
    """
    return [
        Package(
            spdx_id="SPDXRef-Package-go-github.com-gin-gonic-gin",
            name="github.com/gin-gonic/gin",
            version="v1.9.1",
            supplier=SpdxNoAssertion(),
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
            checksums=[
                Checksum(
                    algorithm=ChecksumAlgorithm.SHA256,
                    value="a1b2c3d4e5f67890123456789012345678901234567890123456789012345678",
                )
            ],
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator="pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                )
            ],
        )
    ]


def _get_parent_packages() -> list[Package]:
    """
    Get a list of packages that will be added both to the parent and component
    SBOMs with a CONTAINS relationship. After contextualization, all of these
    packages in the final component SBOM should have the relationships pointing
    to the parent.
    """
    return [
        Package(
            spdx_id="SPDXRef-Package-parent-specific-golang-crypto",
            name="golang.org/x/crypto",
            version="v0.14.0",
            supplier=SpdxNoAssertion(),
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
            checksums=[
                Checksum(
                    algorithm=ChecksumAlgorithm.SHA256,
                    value="9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
            ],
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator="pkg:golang/golang.org/x/crypto@v0.14.0",
                )
            ],
        )
    ]


def _get_component_packages() -> list[Package]:
    """
    Get a list of packages that will be added only to the component SBOM with a
    CONTAINS relationship. After contextualization, all of these packages in
    the final component SBOM should have the relationships still pointing to
    the component.
    """
    return [
        Package(
            spdx_id="SPDXRef-Package-component-specific-golang-crypto",
            name="golang.org/x/stdlib",
            version="v0.14.0",
            supplier=SpdxNoAssertion(),
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
            checksums=[
                Checksum(
                    algorithm=ChecksumAlgorithm.SHA256,
                    value="9876543210abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
            ],
            license_concluded=SpdxNoAssertion(),
            license_declared=SpdxNoAssertion(),
            copyright_text=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator="pkg:golang/golang.org/x/stdlib@v0.14.0",
                )
            ],
        )
    ]


def _add_packages_with_relationships(sbom: InputSBOM, packages: list[Package]) -> None:
    """
    Add packages to an SBOM with CONTAINS relationships to the root package.
    """
    for package in packages:
        relationship = Relationship(
            spdx_element_id=sbom.root_package_spdx_id,
            relationship_type=RelationshipType.CONTAINS,
            related_spdx_element_id=package.spdx_id,
        )
        sbom.document.packages.append(package)
        sbom.document.relationships.append(relationship)


def _create_input_sbom(
    *,
    creation_info_name: str,
    spdx_id: str,
    package_name: str,
    version: str,
    checksum_value: str,
    purl_locator: str,
) -> InputSBOM:
    """
    Create an InputSBOM with the specified parameters.
    """
    creation_info = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=creation_info_name,
        data_license="CC0-1.0",
        document_namespace="https://some.namespace",
        creators=[Actor(ActorType.ORGANIZATION, "Red Hat", "shadowman@redhat.com")],
        created=datetime(2025, 1, 1),
    )

    doc = Document(creation_info)
    root_package = Package(
        spdx_id=spdx_id,
        name=package_name,
        version=version,
        supplier=SpdxNoAssertion(),
        download_location=SpdxNoAssertion(),
        files_analyzed=False,
        checksums=[
            Checksum(
                algorithm=ChecksumAlgorithm.SHA256,
                value=checksum_value,
            )
        ],
        license_concluded=SpdxNoAssertion(),
        license_declared=SpdxNoAssertion(),
        copyright_text=SpdxNoAssertion(),
        external_references=[
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=purl_locator,
            )
        ],
        primary_package_purpose=PackagePurpose.CONTAINER,
    )

    packages = [root_package]

    relationships = [
        Relationship(
            spdx_element_id="SPDXRef-DOCUMENT",
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id=spdx_id,
        )
    ]

    doc.packages = packages
    doc.relationships = relationships
    doc.annotations = []
    return InputSBOM(root_package_spdx_id=spdx_id, document=doc)


def _get_grandparent_input_sbom() -> InputSBOM:
    return _create_input_sbom(
        creation_info_name="grandparent",
        spdx_id="SPDXRef-DocumentRoot-Image-registry.redhat.io-ubi10",
        package_name="./grandparent",
        version="sha256:406b8a55d21d08e8ec6656684a3cd41a63a8f99b71f0eae95fc9c7db4fdbf0f1",
        checksum_value="4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43",
        purl_locator="pkg:oci/registry.redhat.io%2Fubi10@sha256%3A4ab0d32a67e22a27ea3ba4ad00a3a5aee008386ae4f0086c9a720401ab1aca43?arch=amd64",
    )


def _get_parent_input_sbom() -> InputSBOM:
    return _create_input_sbom(
        creation_info_name="parent",
        spdx_id="SPDXRef-DocumentRoot-Image-quay.io-parent-app",
        package_name="./parent",
        version="sha256:b8f9a3c2d7e6f5a4b9c8d1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        checksum_value="b8f9a3c2d7e6f5a4b9c8d1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        purl_locator="pkg:oci/quay.io%2Fparent%2Fapp@sha256%3Ab8f9a3c2d7e6f5a4b9c8d1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1?arch=amd64",
    )


def _get_component_input_sbom() -> InputSBOM:
    return _create_input_sbom(
        creation_info_name="component",
        spdx_id="SPDXRef-DocumentRoot-Image-quay.io-component-app",
        package_name="./component",
        version="sha256:b8f9a3c2d7e6f5a4b9c8d1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        checksum_value="b8f9a3c2d7e6f5a4b9c8d1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
        purl_locator="pkg:oci/quay.io%2Fparent%2Fapp@sha256%3Ab8f9a3c2d7e6f5a4b9c8d1e0f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1?arch=amd64",
    )


def _get_grandparent_gdata(
    tmp_path: Path, common_packages: list[Package]
) -> GenerateData:
    """
    Get a GenerateData instance for grandparent image with all paths and SBOM
    preconfigured.
    """
    data = GenerateData(
        input_sbom_path=tmp_path / "grandparent.input.spdx.json",
        input_sbom=_get_grandparent_input_sbom(),
        output_sbom_path=tmp_path / "grandparent.spdx.json",
        df_json_path=None,
        base_images_path=None,
    )

    _add_packages_with_relationships(data.input_sbom, common_packages)

    write_file(data.input_sbom.document, str(data.input_sbom_path))
    return data


def _get_parent_gdata(
    tmp_path: Path,
    grandparent_img: Image,
    common_packages: list[Package],
    parent_packages: list[Package],
) -> GenerateData:
    """
    Get a GenerateData instance for parent image with all paths and SBOM preconfigured.
    """
    data = GenerateData(
        input_sbom_path=tmp_path / "parent.input.spdx.json",
        input_sbom=_get_parent_input_sbom(),
        output_sbom_path=tmp_path / "parent.spdx.json",
        df_json_path=tmp_path / "parent_df.json",
        base_images_path=tmp_path / "parent_base_images_digest.txt",
    )

    _add_packages_with_relationships(data.input_sbom, common_packages)
    _add_packages_with_relationships(data.input_sbom, parent_packages)

    write_file(data.input_sbom.document, str(data.input_sbom_path))

    assert data.df_json_path
    _write_parsed_dockerfile_json(data.df_json_path, grandparent_img)

    assert data.base_images_path
    _write_base_images_digests(data.base_images_path, grandparent_img)

    return data


def _get_component_gdata(
    tmp_path: Path,
    parent_img: Image,
    common_packages: list[Package],
    parent_packages: list[Package],
    component_packages: list[Package],
) -> GenerateData:
    data = GenerateData(
        input_sbom_path=tmp_path / "component.input.spdx.json",
        input_sbom=_get_component_input_sbom(),
        output_sbom_path=tmp_path / "component.spdx.json",
        df_json_path=tmp_path / "component_df.json",
        base_images_path=tmp_path / "component_base_images_digest.txt",
    )

    _add_packages_with_relationships(data.input_sbom, common_packages)
    _add_packages_with_relationships(data.input_sbom, parent_packages)
    _add_packages_with_relationships(data.input_sbom, component_packages)

    write_file(data.input_sbom.document, str(data.input_sbom_path))

    assert data.df_json_path
    _write_parsed_dockerfile_json(data.df_json_path, parent_img)

    assert data.base_images_path
    _write_base_images_digests(data.base_images_path, parent_img)

    return data


def _write_parsed_dockerfile_json(path: Path, img: Image) -> None:
    """
    Write a parsed dockerfile json to the specified path, replicating a
    DESCENDANT_OF relationship to the passed image.
    """
    parsed_df = {
        "Stages": [
            {
                "BaseName": f"{img.repository}:{img.tag}",
                "From": {"Image": f"{img.repository}:{img.tag}"},
            },
        ]
    }
    with open(path, "w") as fp:
        fp.write(json.dumps(parsed_df))


def _write_base_images_digests(path: Path, img: Image) -> None:
    """
    Write a base image digests file to the specified path, replicating a
    DESCENDANT_OF relationship to the passed image.
    """
    with open(path, "w") as fp:
        fp.write(
            f"{img.repository}:{img.tag} {img.repository}:{img.tag}@{img.digest}\n"
        )


def _get_dependency_chain_spdx_ids(relationships: list[Relationship]) -> list[str]:
    """
    Using the provided relationships, builds a dependency chain based on the
    DESCENDANT_OF relationships. The root element is the first element in the
    list. Assumes there is only a single root.
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
        parent_to_child[rel.spdx_element_id] = str(rel.related_spdx_element_id)

    # build chain starting from root
    spdx_ids = [root]
    current = root
    while current in parent_to_child:
        current = parent_to_child[current]
        spdx_ids.append(current)

    return spdx_ids


def _verify_parent_relationships_contextualized(
    parent_path: Path,
    common_packages: list[Package],
    parent_packages: list[Package],
) -> None:
    """
    Verify that all common packages (packages that are in both the grandparent
    SBOM and the parent SBOM) have their relationships updated to point to the
    grandparent image package and parent-only packages' relationships still
    point to the parent.
    """
    parent_doc: Document = parse_file(str(parent_path))
    dep_chain = _get_dependency_chain_spdx_ids(parent_doc.relationships)

    # verify parent-only packages point to parent
    parent_image_spdx_id = dep_chain[0]
    _verify_relationships(parent_doc, parent_packages, parent_image_spdx_id)

    # verify common packages point to grandparent
    grandparent_image_spdx_id = dep_chain[1]
    _verify_relationships(parent_doc, common_packages, grandparent_image_spdx_id)


def _verify_component_relationships_contextualized(
    component_path: Path,
    common_packages: list[Package],
    parent_packages: list[Package],
    component_packages: list[Package],
) -> None:
    """
    Verify that all common packages (packages that are in both the grandparent
    SBOM and the parent SBOM) have their relationships updated to point to the
    grandparent image package, parent-only packages' relationships still point
    to the parent and component-only packages still point to the component.
    """
    component_doc: Document = parse_file(str(component_path))
    dep_chain = _get_dependency_chain_spdx_ids(component_doc.relationships)

    # verify common packages point to grandparent
    grandparent_image_spdx_id = dep_chain[2]
    _verify_relationships(component_doc, common_packages, grandparent_image_spdx_id)

    # verify parent-component packages point to parent
    parent_image_spdx_id = dep_chain[1]
    _verify_relationships(component_doc, parent_packages, parent_image_spdx_id)

    # verify component-only packages point to component
    component_image_spdx_id = dep_chain[0]
    _verify_relationships(component_doc, component_packages, component_image_spdx_id)


def _verify_relationships(doc: Document, packages: list[Package], spdx_id: str) -> None:
    """
    Verify that the relationships of the provided packages point to the
    specified spdx id.
    """
    package_set = {pkg.spdx_id for pkg in packages}
    for pkg in packages:
        for rel in doc.relationships:
            if rel.related_spdx_element_id != pkg.spdx_id:
                continue

            assert rel.spdx_element_id == spdx_id, (
                f"Relationship of the package with spdx id {pkg.spdx_id} "
                "points to wrong spdx id."
            )
            package_set.remove(pkg.spdx_id)

    assert len(package_set) == 0, (
        f"SPDX IDs of packages that were not found: {package_set}"
    )
