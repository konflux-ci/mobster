import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser

from mobster.cmd.generate.oci_image.spdx_utils import (
    DocumentIndexOCI,
    KonfluxAnnotationManager,
    find_spdx_root_packages,
    find_spdx_root_packages_spdxid,
    find_spdx_root_relationships,
    get_annotations_by_spdx_id,
    is_virtual_root,
    normalize_actor,
    normalize_package,
    normalize_sbom,
    redirect_current_roots_to_new_root,
    redirect_spdx_virtual_root_to_new_root,
    update_package_in_spdx_sbom,
)
from mobster.image import Image
from mobster.sbom.spdx import get_mobster_tool_string, get_package_purl
from tests.conftest import create_annotation_with_spdx_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["actor", "expected_output"],
    [
        ("foo", "Tool: foo"),
        ("Tool: foo", "Tool: foo"),
        ("Person: foo", "Person: foo"),
        ("Organization: foo", "Organization: foo"),
        ("NOASSERTION", "NOASSERTION"),
    ],
)
async def test_normalize_actor(actor: str, expected_output: str) -> None:
    assert await normalize_actor(actor) == expected_output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["input_package_dict", "expected_output_dict"],
    [
        (
            {"SPDXID": "SPDXRef-foo"},
            {"SPDXID": "SPDXRef-foo", "downloadLocation": "NOASSERTION", "name": ""},
        ),
        (
            {
                "name": "foo",
                "supplier": "bar",
            },
            {
                "name": "foo",
                "supplier": "Tool: bar",
                "downloadLocation": "NOASSERTION",
            },
        ),
    ],
)
async def test_normalize_package(
    input_package_dict: dict[str, Any], expected_output_dict: dict[str, Any]
) -> None:
    package_dict = input_package_dict.copy()
    await normalize_package(package_dict)
    assert package_dict == expected_output_dict


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["input_sbom_dict", "expected_sbom_dict"],
    [
        (
            {"packages": [{"SPDXID": "SPDXRef-foo"}]},
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "dataLicense": "CC0-1.0",
                "spdxVersion": "SPDX-2.3",
                "documentNamespace": "https://konflux-ci.dev/spdxdocs/"
                "MOBSTER:UNFILLED_NAME (please update this field)-1",
                "name": "MOBSTER:UNFILLED_NAME (please update this field)",
                "creationInfo": {
                    "created": "1970-01-01T00:00:00Z",
                    "creators": [get_mobster_tool_string()],
                },
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "downloadLocation": "NOASSERTION",
                        "name": "",
                    }
                ],
            },
        )
    ],
)
@patch("mobster.sbom.spdx.uuid4")
async def test_normalize_sbom(
    mock_uuid: MagicMock,
    input_sbom_dict: dict[str, Any],
    expected_sbom_dict: dict[str, Any],
) -> None:
    mock_uuid.return_value = 1
    sbom_dict = input_sbom_dict.copy()
    await normalize_sbom(sbom_dict)
    assert sbom_dict == expected_sbom_dict


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "sbom_fields",
        "expected_relationship_object",
        "expected_spdxid",
        "expected_package_object",
    ],
    [
        (
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "foo",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                ],
            },
            [
                Relationship(
                    relationship_type=RelationshipType.DESCRIBES,
                    spdx_element_id="SPDXRef-DOCUMENT",
                    related_spdx_element_id="SPDXRef-foo",
                )
            ],
            ["SPDXRef-foo"],
            [
                Package(
                    spdx_id="SPDXRef-foo",
                    name="foo",
                    download_location=SpdxNoAssertion(),
                )
            ],
        ),
        (
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "foo",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "relatedSpdxElement": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBED_BY",
                        "spdxElementId": "SPDXRef-foo",
                    },
                ],
            },
            [
                Relationship(
                    relationship_type=RelationshipType.DESCRIBED_BY,
                    related_spdx_element_id="SPDXRef-DOCUMENT",
                    spdx_element_id="SPDXRef-foo",
                )
            ],
            ["SPDXRef-foo"],
            [
                Package(
                    spdx_id="SPDXRef-foo",
                    name="foo",
                    download_location=SpdxNoAssertion(),
                )
            ],
        ),
    ],
)
async def test_find_spdx_root(
    spdx_sbom_skeleton: dict[str, Any],
    sbom_fields: dict[str, Any],
    expected_relationship_object: list[Relationship],
    expected_spdxid: list[str],
    expected_package_object: list[Package],
) -> None:
    new_sbom = spdx_sbom_skeleton.copy()
    new_sbom.update(sbom_fields)
    sbom_doc_object = JsonLikeDictParser().parse(new_sbom)  # type: ignore[no-untyped-call]
    assert expected_relationship_object == await find_spdx_root_relationships(
        sbom_doc_object
    )
    assert expected_spdxid == await find_spdx_root_packages_spdxid(sbom_doc_object)
    assert expected_package_object == await find_spdx_root_packages(sbom_doc_object)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["package", "is_virtual"],
    [
        (
            Package(
                spdx_id="SPDXRef-foo", name="", download_location=SpdxNoAssertion()
            ),
            True,
        ),
        (
            Package(
                spdx_id="SPDXRef-foo", name="./foo", download_location=SpdxNoAssertion()
            ),
            True,
        ),
        (
            Package(
                spdx_id="SPDXRef-foo",
                name="/path/to/file",
                download_location=SpdxNoAssertion(),
            ),
            True,
        ),
        (
            Package(
                spdx_id="SPDXRef-foo", name="foo", download_location=SpdxNoAssertion()
            ),
            False,
        ),
    ],
)
async def test_is_virtual_root(package: Package, is_virtual: bool) -> None:
    assert is_virtual == await is_virtual_root(package)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["additional_fields", "expected_relationships"],
    [
        (
            {
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "relatedSpdxElement": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBED_BY",
                        "spdxElementId": "SPDXRef-foo",
                    },
                ],
            },
            [
                Relationship(
                    spdx_element_id="SPDXRef-bar",
                    relationship_type=RelationshipType.BUILD_TOOL_OF,
                    related_spdx_element_id="SPDXRef-spam",
                ),
                Relationship(
                    spdx_element_id="SPDXRef-spam",
                    relationship_type=RelationshipType.DESCRIBED_BY,
                    related_spdx_element_id="SPDXRef-DOCUMENT",
                ),
            ],
        )
    ],
)
async def test_redirect_spdx_virtual_root_to_new_root(
    spdx_sbom_skeleton: dict[str, Any],
    additional_fields: dict[str, Any],
    expected_relationships: list[Relationship],
) -> None:
    new_sbom = spdx_sbom_skeleton.copy()
    new_sbom.update(additional_fields)
    sbom_doc_object = JsonLikeDictParser().parse(new_sbom)  # type: ignore[no-untyped-call]
    await redirect_spdx_virtual_root_to_new_root(
        sbom_doc_object, "SPDXRef-foo", "SPDXRef-spam"
    )

    assert sbom_doc_object.relationships == expected_relationships


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["additional_fields", "expected_outcome", "new_root_spdxid"],
    [
        pytest.param(
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "foo",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-spam",
                        "name": "spam",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "relatedSpdxElement": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBED_BY",
                        "spdxElementId": "SPDXRef-foo",
                    },
                ],
            },
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
                packages=[
                    Package(
                        spdx_id="SPDXRef-foo",
                        name="foo",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-bar",
                        name="bar",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-spam",
                        name="spam",
                        download_location=SpdxNoAssertion(),
                    ),
                ],
                relationships=[
                    Relationship(
                        spdx_element_id="SPDXRef-bar",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-spam",
                        relationship_type=RelationshipType.CONTAINS,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-DOCUMENT",
                        relationship_type=RelationshipType.DESCRIBES,
                        related_spdx_element_id="SPDXRef-spam",
                    ),
                ],
            ),
            "SPDXRef-spam",
            id="Add new root",
        ),
        pytest.param(
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-spam",
                        "name": "spam",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relatedSpdxElement": "SPDXRef-foo",
                        "relationshipType": "DESCRIBES",
                    },
                ],
            },
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
                packages=[
                    Package(
                        spdx_id="SPDXRef-bar",
                        name="bar",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-spam",
                        name="spam",
                        download_location=SpdxNoAssertion(),
                    ),
                ],
                relationships=[
                    Relationship(
                        spdx_element_id="SPDXRef-bar",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-spam",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-DOCUMENT",
                        relationship_type=RelationshipType.DESCRIBES,
                        related_spdx_element_id="SPDXRef-spam",
                    ),
                ],
            ),
            "SPDXRef-spam",
            id="Replace virtual root",
        ),
    ],
)
async def test_redirect_current_roots_to_new_root(
    spdx_sbom_skeleton: dict[str, Any],
    additional_fields: dict[str, Any],
    expected_outcome: Document,
    new_root_spdxid: str,
) -> None:
    new_sbom = spdx_sbom_skeleton.copy()
    new_sbom.update(additional_fields)
    sbom_doc_object = JsonLikeDictParser().parse(new_sbom)  # type: ignore[no-untyped-call]
    await redirect_current_roots_to_new_root(sbom_doc_object, new_root_spdxid)
    assert sbom_doc_object == expected_outcome


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.spdx_utils.datetime")
@pytest.mark.parametrize(
    ["additional_fields", "expected_outcome", "image_object", "is_builder_image"],
    [
        pytest.param(
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "foo",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "relatedSpdxElement": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBED_BY",
                        "spdxElementId": "SPDXRef-foo",
                    },
                ],
            },
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
                packages=[
                    Package(
                        spdx_id="SPDXRef-image-ham-dcd06c35ea63407034801d9c725713f2b346d29080816489f03276da3ff839dc",
                        name="ham",
                        download_location=SpdxNoAssertion(),
                        version="v1",
                        files_analyzed=False,
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION,
                            name="Red Hat",
                        ),
                        checksums=[
                            Checksum(
                                algorithm=ChecksumAlgorithm.SHA256,
                                value="1",
                            ),
                        ],
                        license_declared=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/ham@sha256:1?repository_url=foo.bar/foobar/ham",
                            ),
                        ],
                    ),
                    Package(
                        spdx_id="SPDXRef-foo",
                        name="foo",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-bar",
                        name="bar",
                        download_location=SpdxNoAssertion(),
                    ),
                ],
                relationships=[
                    Relationship(
                        spdx_element_id="SPDXRef-bar",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-image-ham-dcd06c35ea63407034801d9c725713f2b346d29080816489f03276da3ff839dc",
                        relationship_type=RelationshipType.CONTAINS,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-DOCUMENT",
                        relationship_type=RelationshipType.DESCRIBES,
                        related_spdx_element_id="SPDXRef-image-ham-dcd06c35ea63407034801d9c725713f2b346d29080816489f03276da3ff839dc",
                    ),
                ],
            ),
            Image.from_image_index_url_and_digest(
                image_tag_pullspec="foo.bar/foobar/ham:v1", image_digest="sha256:1"
            ),
            False,
            id="Add new root",
        ),
        pytest.param(
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relatedSpdxElement": "SPDXRef-foo",
                        "relationshipType": "DESCRIBES",
                    },
                ],
            },
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
                packages=[
                    Package(
                        spdx_id="SPDXRef-image-spam-5112d254d4099f4073a2aceafb3c8e08ed9f9d602732f2acb709769d4524bc3f",
                        name="spam",
                        download_location=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/spam@sha256:1?repository_url=foo.bar/foobar/spam",
                            ),
                        ],
                        license_declared=SpdxNoAssertion(),
                        checksums=[
                            Checksum(
                                algorithm=ChecksumAlgorithm.SHA256,
                                value="1",
                            )
                        ],
                        files_analyzed=False,
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION, name="Red Hat"
                        ),
                        version="v1",
                    ),
                    Package(
                        spdx_id="SPDXRef-bar",
                        name="bar",
                        download_location=SpdxNoAssertion(),
                    ),
                ],
                relationships=[
                    Relationship(
                        spdx_element_id="SPDXRef-bar",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-image-spam-5112d254d4099f4073a2aceafb3c8e08ed9f9d602732f2acb709769d4524bc3f",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-DOCUMENT",
                        relationship_type=RelationshipType.DESCRIBES,
                        related_spdx_element_id="SPDXRef-image-spam-5112d254d4099f4073a2aceafb3c8e08ed9f9d602732f2acb709769d4524bc3f",
                    ),
                ],
            ),
            Image.from_image_index_url_and_digest(
                image_tag_pullspec="foo.bar/foobar/spam:v1", image_digest="sha256:1"
            ),
            False,
            id="Replace virtual root",
        ),
        pytest.param(
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "foo",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-spam",
                        "name": "spam",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "relatedSpdxElement": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBED_BY",
                        "spdxElementId": "SPDXRef-foo",
                    },
                ],
            },
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
                annotations=[
                    Annotation(
                        annotation_type=AnnotationType.OTHER,
                        spdx_id="SPDXRef-image-ham-dcd06c35ea63407034801d9c725713f2b346d29080816489f03276da3ff839dc",
                        annotation_comment='{"name":"konflux:container:is_builder_image:additional_builder_image","value":"script-runner-image"}',
                        annotator=Actor(
                            actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                        ),
                        annotation_date=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    )
                ],
                packages=[
                    Package(
                        spdx_id="SPDXRef-image-ham-dcd06c35ea63407034801d9c725713f2b346d29080816489f03276da3ff839dc",
                        name="ham",
                        download_location=SpdxNoAssertion(),
                        version="v1",
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION,
                            name="Red Hat",
                        ),
                        files_analyzed=False,
                        checksums=[
                            Checksum(
                                algorithm=ChecksumAlgorithm.SHA256,
                                value="1",
                            ),
                        ],
                        license_declared=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/ham@sha256:1?repository_url=foo.bar/foobar/ham",
                            ),
                        ],
                        attribution_texts=[],
                    ),
                    Package(
                        spdx_id="SPDXRef-foo",
                        name="foo",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-bar",
                        name="bar",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-spam",
                        name="spam",
                        download_location=SpdxNoAssertion(),
                    ),
                ],
                relationships=[
                    Relationship(
                        spdx_element_id="SPDXRef-bar",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-foo",
                        relationship_type=RelationshipType.DESCRIBED_BY,
                        related_spdx_element_id="SPDXRef-DOCUMENT",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-image-ham-dcd06c35ea63407034801d9c725713f2b346d29080816489f03276da3ff839dc",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                ],
            ),
            Image.from_image_index_url_and_digest(
                image_tag_pullspec="foo.bar/foobar/ham:v1", image_digest="sha256:1"
            ),
            True,
            id="Add a builder image",
        ),
    ],
)
async def test_update_package_in_spdx_sbom(
    mock_datetime: MagicMock,
    spdx_sbom_skeleton: dict[str, Any],
    additional_fields: dict[str, Any],
    expected_outcome: Document,
    image_object: Image,
    is_builder_image: bool,
) -> None:
    mock_datetime.now.return_value = datetime.datetime(1970, 1, 1, 0, 0, 0)
    new_sbom = spdx_sbom_skeleton.copy()
    new_sbom.update(additional_fields)
    sbom_doc_object = JsonLikeDictParser().parse(new_sbom)  # type: ignore[no-untyped-call]
    await update_package_in_spdx_sbom(sbom_doc_object, image_object, is_builder_image)
    assert sbom_doc_object == expected_outcome


@pytest.mark.parametrize(
    ["doc_annotations", "spdx_id", "expected_length"],
    [
        # Successful retrieval
        (
            [
                create_annotation_with_spdx_id("SPDXRef-annotation1"),
                create_annotation_with_spdx_id("SPDXRef-annotation2"),
                create_annotation_with_spdx_id("SPDXRef-annotation2"),
            ],
            "SPDXRef-annotation2",
            2,
        ),
        # Not found
        (
            [
                create_annotation_with_spdx_id("SPDXRef-annotation1"),
            ],
            "SPDXRef-nonexistent",
            0,
        ),
        # Empty annotations list
        (
            [],
            "SPDXRef-annotation",
            0,
        ),
    ],
)
def test_get_annotations_by_spdx_id(
    doc_annotations: list[Annotation] | None,
    spdx_id: str,
    expected_length: int,
) -> None:
    """Test get_annotations_by_spdx_id function with various document configurations."""
    doc = MagicMock(spec=Document)
    doc.annotations = doc_annotations

    result = get_annotations_by_spdx_id(doc, spdx_id)
    assert len(result) == expected_length
    if result:
        assert all(annot.spdx_id == spdx_id for annot in result)


@pytest.mark.parametrize(
    ["package", "expected_result"],
    [
        pytest.param(
            Package(
                "SPDXRef-package",
                "test-package",
                SpdxNoAssertion(),
                external_references=[
                    ExternalPackageRef(
                        ExternalPackageRefCategory.PACKAGE_MANAGER,
                        "purl",
                        "pkg:npm/test-package@1.0.0",
                    )
                ],
            ),
            "pkg:npm/test-package@1.0.0",
            id="successful-purl-extraction",
        ),
        pytest.param(
            Package("SPDXRef-package", "test-package", SpdxNoAssertion()),
            None,
            id="no-external-references",
        ),
        pytest.param(
            Package(
                "SPDXRef-package",
                "test-package",
                SpdxNoAssertion(),
                external_references=[
                    ExternalPackageRef(
                        ExternalPackageRefCategory.SECURITY,
                        "purl",
                        "pkg:npm/test-package@1.0.0",
                    )
                ],
            ),
            None,
            id="wrong-external-reference-category",
        ),
        pytest.param(
            Package(
                "SPDXRef-package",
                "test-package",
                SpdxNoAssertion(),
                external_references=[
                    ExternalPackageRef(
                        ExternalPackageRefCategory.PACKAGE_MANAGER,
                        "maven",
                        "pkg:npm/test-package@1.0.0",
                    )
                ],
            ),
            None,
            id="wrong-external-reference-type",
        ),
        pytest.param(
            Package(
                "SPDXRef-package",
                "test-package",
                SpdxNoAssertion(),
                external_references=[
                    ExternalPackageRef(
                        ExternalPackageRefCategory.SECURITY,
                        "cpe",
                        "cpe:2.3:a:test:package:1.0.0",
                    ),
                    ExternalPackageRef(
                        ExternalPackageRefCategory.PACKAGE_MANAGER,
                        "purl",
                        "pkg:npm/test-package@1.0.0",
                    ),
                ],
            ),
            "pkg:npm/test-package@1.0.0",
            id="multiple-external-references",
        ),
    ],
)
def test_get_package_purl(package: Package, expected_result: str | None) -> None:
    assert get_package_purl(package) == expected_result


@pytest.fixture
def simple_spdx_document() -> Document:
    """SPDX document with basic packages for testing."""
    packages = [
        Package(
            spdx_id="SPDXRef-PackageA",
            name="package-a",
            download_location=SpdxNoAssertion(),
        ),
        Package(
            spdx_id="SPDXRef-PackageB",
            name="package-b",
            download_location=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    ExternalPackageRefCategory.PACKAGE_MANAGER,
                    "purl",
                    "pkg:npm/package-b@1.0.0",
                )
            ],
        ),
        Package(
            spdx_id="SPDXRef-PackageC",
            name="package-c",
            download_location=SpdxNoAssertion(),
        ),
    ]

    return Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.example.com/doc",
            created=datetime.datetime.now(),
            creators=[Actor(ActorType.TOOL, "test")],
        ),
        packages=packages,
    )


@pytest.fixture
def image_spdx_document() -> Document:
    """SPDX document with image packages for testing."""
    packages = [
        Package(
            spdx_id="SPDXRef-RegularPackage",
            name="regular-package",
            download_location=SpdxNoAssertion(),
        ),
        Package(
            spdx_id="SPDXRef-image-container",
            name="container-image",
            download_location=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    ExternalPackageRefCategory.PACKAGE_MANAGER,
                    "purl",
                    "pkg:oci/container@sha256:abc123?repository_url=registry.example.com/container",
                )
            ],
        ),
        Package(
            spdx_id="SPDXRef-image-base",
            name="base-image",
            download_location=SpdxNoAssertion(),
            external_references=[
                ExternalPackageRef(
                    ExternalPackageRefCategory.PACKAGE_MANAGER,
                    "purl",
                    "pkg:oci/base-image@sha256:def456?repository_url=registry.example.com/base",
                )
            ],
        ),
    ]

    return Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="image-doc",
            document_namespace="https://test.example.com/image-doc",
            created=datetime.datetime.now(),
            creators=[Actor(ActorType.TOOL, "test")],
        ),
        packages=packages,
        annotations=[
            KonfluxAnnotationManager.builder_image("SPDXRef-image-container", 1),
            KonfluxAnnotationManager.builder_image("SPDXRef-image-base", 0),
        ],
    )


@pytest.fixture
def relationship_spdx_document() -> Document:
    """SPDX document with relationships and annotations."""
    packages = [
        Package(
            spdx_id="SPDXRef-Parent", name="parent", download_location=SpdxNoAssertion()
        ),
        Package(
            spdx_id="SPDXRef-Child", name="child", download_location=SpdxNoAssertion()
        ),
        Package(
            spdx_id="SPDXRef-Other", name="other", download_location=SpdxNoAssertion()
        ),
    ]

    relationships = [
        Relationship(
            spdx_element_id="SPDXRef-Parent",
            relationship_type=RelationshipType.CONTAINS,
            related_spdx_element_id="SPDXRef-Child",
        )
    ]

    annotations = [
        Annotation(
            spdx_id="SPDXRef-Child",
            annotation_type=AnnotationType.OTHER,
            annotator=Actor(ActorType.TOOL, "test"),
            annotation_comment="test annotation",
            annotation_date=datetime.datetime.now(),
        )
    ]

    return Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="rel-doc",
            document_namespace="https://test.example.com/rel-doc",
            created=datetime.datetime.now(),
            creators=[Actor(ActorType.TOOL, "test")],
        ),
        packages=packages,
        relationships=relationships,
        annotations=annotations,
    )


@pytest.fixture
def builder_image_document() -> Document:
    """SPDX document with builder image for intermediate testing."""
    builder_annotation = Annotation(
        spdx_id="SPDXRef-image-builder",
        annotation_type=AnnotationType.OTHER,
        annotator=Actor(ActorType.TOOL, "konflux:jsonencoded"),
        annotation_comment='{"name":"konflux:container:is_builder_image:for_stage","value":"1"}',
        annotation_date=datetime.datetime.now(),
    )

    packages = [
        Package(
            spdx_id="SPDXRef-image-builder",
            name="builder-image",
            download_location=SpdxNoAssertion(),
            files_analyzed=False,
        )
    ]

    return Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="builder-doc",
            document_namespace="https://test.example.com/builder-doc",
            created=datetime.datetime.now(),
            creators=[Actor(ActorType.TOOL, "test")],
        ),
        packages=packages,
        annotations=[builder_annotation],
    )


def test_document_index_package_lookup(simple_spdx_document: Document) -> None:
    """Test basic package lookup operations."""
    index = DocumentIndexOCI(simple_spdx_document)

    ctx = index.package_by_spdx_id("SPDXRef-PackageA")
    assert ctx.pkg.name == "package-a"

    with pytest.raises(KeyError):
        index.package_by_spdx_id("SPDXRef-NonExistent")

    purl_ctxs = index.packages_by_purl("pkg:npm/package-b@1.0.0")
    assert len(purl_ctxs) == 1
    assert purl_ctxs[0].pkg.name == "package-b"

    assert index.packages_by_purl("nonexistent") == []

    all_contexts = list(index.package_contexts())
    assert len(all_contexts) == 3


@pytest.mark.parametrize(
    "pullspec,expected_found",
    [
        ("registry.example.com/container@sha256:abc123", True),
        ("nonexistent.com/image@sha256:xyz", False),
    ],
)
def test_document_index_image_packages(
    image_spdx_document: Document, pullspec: str, expected_found: bool
) -> None:
    """Test image package filtering and lookup."""
    index = DocumentIndexOCI(image_spdx_document)

    image_packages = index.image_packages()
    assert len(image_packages) == 2  # Only packages with SPDXRef-image prefix
    image_spdx_ids = [ctx.pkg.spdx_id for ctx in image_packages]
    assert "SPDXRef-image-container" in image_spdx_ids
    assert "SPDXRef-image-base" in image_spdx_ids
    assert "SPDXRef-RegularPackage" not in image_spdx_ids

    result = index.image_package_by_pullspec(pullspec)
    if expected_found:
        assert result is not None
        assert result.pkg.spdx_id == "SPDXRef-image-container"
    else:
        assert result is None


def test_document_index_relationships_annotations(
    relationship_spdx_document: Document,
) -> None:
    """Test relationship and annotation indexing."""
    index = DocumentIndexOCI(relationship_spdx_document)

    parent_ctx = index.package_by_spdx_id("SPDXRef-Parent")
    assert len(parent_ctx.parent_relationships) == 1
    assert parent_ctx.parent_relationships[0].related_spdx_element_id == "SPDXRef-Child"

    child_ctx = index.package_by_spdx_id("SPDXRef-Child")

    assert len(child_ctx.annotations) == 1
    assert child_ctx.annotations[0].annotation_comment == "test annotation"

    other_ctx = index.package_by_spdx_id("SPDXRef-Other")
    assert len(other_ctx.parent_relationships) == 0
    assert len(other_ctx.annotations) == 0


def test_document_index_ensure_intermediate_image(
    builder_image_document: Document,
) -> None:
    """Test intermediate image package creation."""
    index = DocumentIndexOCI(builder_image_document)

    builder_ctx = index.package_by_spdx_id("SPDXRef-image-builder")

    intermediate_ctx = index.ensure_intermediate_image_package(builder_ctx)

    assert intermediate_ctx.pkg.spdx_id.endswith("-intermediate")
    assert intermediate_ctx.pkg.name.endswith("-intermediate")

    descendant_rels = intermediate_ctx.filter_parent_relationships(
        RelationshipType.DESCENDANT_OF
    )
    assert len(descendant_rels) == 1
    assert descendant_rels[0].related_spdx_element_id == "SPDXRef-image-builder"

    int_annotation = intermediate_ctx.intermediate_image_annotation
    assert int_annotation is not None
    assert int_annotation.stage_index == 1

    # Test idempotency - calling ensure_intermediate_image_package again should
    # return the same package
    intermediate_ctx2 = index.ensure_intermediate_image_package(builder_ctx)
    assert intermediate_ctx.pkg.spdx_id == intermediate_ctx2.pkg.spdx_id


def test_document_index_reparent_relationship(
    relationship_spdx_document: Document,
) -> None:
    """Test relationship reparenting functionality."""
    index = DocumentIndexOCI(relationship_spdx_document)

    parent_ctx = index.package_by_spdx_id("SPDXRef-Parent")
    relationship = parent_ctx.parent_relationships[0]

    index.reparent_relationship(relationship, "SPDXRef-Other")

    assert relationship.spdx_element_id == "SPDXRef-Other"
    assert len(parent_ctx.parent_relationships) == 0

    new_parent_ctx = index.package_by_spdx_id("SPDXRef-Other")
    assert len(new_parent_ctx.parent_relationships) == 1
    assert new_parent_ctx.parent_relationships[0] == relationship
