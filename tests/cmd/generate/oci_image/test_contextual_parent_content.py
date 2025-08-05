import datetime
import json
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image import (  # type: ignore[attr-defined]
    adjust_parent_image_relationship_in_legacy_sbom,
    adjust_parent_image_spdx_element_ids,
    calculate_component_only_content,
    create_contextual_sbom,
    download_parent_image_sbom,
    get_used_parent_image_from_legacy_sbom,
    remove_parent_image_builder_records,
)
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM


@pytest.mark.asyncio
async def test_get_used_parent_image_from_legacy_sbom() -> None:
    mock_doc = MagicMock()
    mock_doc.annotations = [
        Annotation(
            "SPDXRef-foo",
            AnnotationType.OTHER,
            Actor(ActorType.TOOL, "bar"),
            datetime.datetime.now(),
            "le comment",
        ),
        Annotation(
            "SPDXRef-spam",
            AnnotationType.OTHER,
            Actor(ActorType.TOOL, "ham"),
            datetime.datetime.now(),
            '{ "name": "konflux:container:is_base_image",   "value": "true" }',
        ),
    ]
    assert await get_used_parent_image_from_legacy_sbom(mock_doc) == "SPDXRef-spam"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["image_or_index", "arch"],
    [
        (Image("quay.io/foo", "sha256:a"), "amd64"),
        (
            IndexImage(
                "quay.io/foo",
                "sha256:a",
                children=[
                    Image("quay.io/foo", "sha256:1"),
                    Image("quay.io/foo", "sha256:2", arch="amd64"),
                ],
            ),
            "amd64",
        ),
        (Image("quay.io/foo", "sha256:a"), ""),
    ],
)
@patch("mobster.oci.cosign.CosignClient.fetch_sbom")
@patch("mobster.image.Image.from_repository_digest_manifest")
async def test_download_parent_image_sbom(
    mock_get_image_or_index: AsyncMock,
    mock_fetch_sbom: AsyncMock,
    image_or_index: Image | IndexImage,
    arch: str,
    spdx_parent_sbom_bytes: bytes,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_get_image_or_index.return_value = image_or_index
    mock_fetch_sbom.return_value = SBOM.from_cosign_output(
        spdx_parent_sbom_bytes, "quay.io/foo"
    )
    sbom_doc = await download_parent_image_sbom(Image("quay.io/foo", "sha256:a"), arch)
    assert sbom_doc == json.loads(spdx_parent_sbom_bytes)
    assert sbom_doc.get("spdxVersion", "").startswith("SPDX-2.")
    assert (
        f"[Parent content] The specific arch was successfully "
        f"located for ref quay.io/foo@sha256:a and arch {arch}" in caplog.messages
    )


@pytest.mark.asyncio
async def test_download_parent_image_sbom_no_image(caplog: LogCaptureFixture) -> None:
    caplog.set_level("INFO")
    assert await download_parent_image_sbom(None, "") is None
    assert (
        "Contextual mechanism won't be used, there is no parent image."
        in caplog.messages
    )


@pytest.mark.asyncio
@patch("mobster.oci.cosign.CosignClient.fetch_sbom")
@patch("mobster.image.Image.from_repository_digest_manifest")
async def test_download_parent_image_sbom_no_arch_match(
    mock_from_repo_manifest: AsyncMock,
    mock_fetch_sbom: AsyncMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    index_image = IndexImage(
        "foo", "sha256:1", children=[Image("foo", "sha256:2", arch="spam")]
    )
    mock_from_repo_manifest.return_value = index_image
    await download_parent_image_sbom(Image("foo", "sha256:1"), "bar")
    mock_fetch_sbom.assert_awaited_once_with(index_image)
    assert (
        "[Parent content] Only the index image of parent "
        "was found for ref foo@sha256:1 and arch bar" in caplog.messages
    )


@pytest.mark.asyncio
@patch("mobster.oci.cosign.CosignClient.fetch_sbom")
@patch("mobster.image.Image.from_repository_digest_manifest")
async def test_download_parent_image_sbom_no_sbom(
    mock_from_repo_manifest: AsyncMock,
    mock_fetch_sbom: AsyncMock,
    caplog: LogCaptureFixture,
) -> None:
    mock_fetch_sbom.side_effect = SBOMError("No SBOM :(")
    assert (
        await download_parent_image_sbom(
            Image("foo", "sha256:1"), "totally existing arch"
        )
        is None
    )
    assert "Contextual mechanism won't be used, there is no parent image SBOM."


@pytest.mark.asyncio
@patch("mobster.oci.cosign.CosignClient.fetch_sbom")
@patch("mobster.image.Image.from_repository_digest_manifest")
async def test_download_parent_image_sbom_cdx(
    mock_from_repo_manifest: AsyncMock,
    mock_fetch_sbom: AsyncMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")
    mock_fetch_sbom.return_value = SBOM(
        {"bomFormat": "CycloneDX", "specVersion": "1.6"}, "sha256:1", "foo.sbom"
    )
    assert await download_parent_image_sbom(Image("foo", "sha256:1"), "bar") is None
    assert (
        "Contextual mechanism won't be used, SBOM format is not supported for "
        "this workflow." in caplog.messages
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_relationship_in_legacy_sbom(
    spdx_parent_sbom: Document,
) -> None:
    """
    Downloaded parent image has not been contextualized yet,
    but has been produced by legacy SBOM generator in konflux -
    parent of this parent is marked in packages.annotations
    Relationship needs to be adjusted to DESCENDANT_OF.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)

    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = (
        await adjust_parent_image_relationship_in_legacy_sbom(
            spdx_parent_edit, grandparent_spdx_id
        )
    ).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 1
    assert (
        descendant_of_relationship[0].spdx_element_id == "SPDXRef-image"
    )  # self (downloaded parent image)
    # is descendant of
    assert (
        descendant_of_relationship[0].related_spdx_element_id
        == "SPDXRef-image-registry.access.redhat.com/ubi9"
    )  # parent image of this parent image


@pytest.mark.asyncio
async def test_adjust_parent_image_relationship_in_legacy_sbom_no_change(
    spdx_parent_sbom: Document,
    caplog: LogCaptureFixture,
) -> None:
    """
    Downloaded parent image has been already
    contextualized or had already DESCENDANT_OF
    relationship set.
    """
    caplog.set_level("DEBUG")
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships[-1].spdx_element_id = "SPDXRef-image"
    spdx_parent_edit.relationships[
        -1
    ].relationship_type = RelationshipType.DESCENDANT_OF
    spdx_parent_edit.relationships[
        -1
    ].related_spdx_element_id = "SPDXRef-image-registry.access.redhat.com/ubi9"

    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = (
        await adjust_parent_image_relationship_in_legacy_sbom(
            spdx_parent_edit, grandparent_spdx_id
        )
    ).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 1
    assert (
        descendant_of_relationship[0].spdx_element_id == "SPDXRef-image"
    )  # self (downloaded parent image)
    # is descendant of
    assert (
        descendant_of_relationship[0].related_spdx_element_id
        == "SPDXRef-image-registry.access.redhat.com/ubi9"
    )  # parent image of this parent image
    assert (
        "[Parent image content] Downloaded parent image "
        "content already contains DESCENDANT_OF relationship." in caplog.messages
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_relationship_in_legacy_sbom_unknown_relationship(
    spdx_parent_sbom: Document,
    caplog: LogCaptureFixture,
) -> None:
    """
    Downloaded parent image has some unknown relationship with its parent image
    and thus we cannot use convert_to_descendant_of_relationship function.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships[
        -1
    ].spdx_element_id = "SPDXRef-image-registry.access.redhat.com/ubi9"
    spdx_parent_edit.relationships[-1].relationship_type = RelationshipType.OTHER
    spdx_parent_edit.relationships[-1].related_spdx_element_id = "SPDXRef-image"

    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = (
        await adjust_parent_image_relationship_in_legacy_sbom(
            spdx_parent_edit, grandparent_spdx_id
        )
    ).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 0
    assert (
        "[Parent image content] Targeted SPDXID "
        "SPDXRef-image-registry.access.redhat.com/ubi9 "
        "does not bear BUILD_TOOL_OF relationship "
        "but RelationshipType.OTHER relationship." in caplog.messages
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_relationship_in_legacy_sbom_no_relationship(
    spdx_parent_sbom: Document,
    caplog: LogCaptureFixture,
) -> None:
    """
    Missing relationship between parent image and its parent image.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships.pop(-1)

    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = (
        await adjust_parent_image_relationship_in_legacy_sbom(
            spdx_parent_edit, grandparent_spdx_id
        )
    ).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 0

    assert (
        "[Parent image content] Targeted SPDXID "
        "SPDXRef-image-registry.access.redhat.com/ubi9 "
        "does not bear any relationship!" in caplog.messages
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_relationship_in_legacy_sbom_multiple_relationships(
    spdx_parent_sbom: Document,
    caplog: LogCaptureFixture,
) -> None:
    """
    Multiple relationships between parent image and its parent image.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.relationships[-1] = Relationship(
        spdx_element_id="SPDXRef-image-registry.access.redhat.com/ubi9",
        relationship_type=RelationshipType.BUILD_TOOL_OF,
        related_spdx_element_id="SPDXRef-image",
    )
    spdx_parent_edit.relationships.append(
        Relationship(
            spdx_element_id="SPDXRef-image-registry.access.redhat.com/ubi9",
            relationship_type=RelationshipType.BUILD_TOOL_OF,
            related_spdx_element_id="SPDXRef-image-what?",
        )
    )

    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = (
        await adjust_parent_image_relationship_in_legacy_sbom(
            spdx_parent_edit, grandparent_spdx_id
        )
    ).relationships
    descendant_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.DESCENDANT_OF,
            relationships,
        )
    )
    assert len(descendant_of_relationship) == 0
    assert (
        "[Parent image content] Targeted SPDXID "
        "SPDXRef-image-registry.access.redhat.com/ubi9 "
        "has more than one relationship. This is not expected, "
        "skipping modification." in caplog.messages
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_relationship_in_legacy_sbom_parent_not_marked(
    spdx_parent_sbom: Document,
    caplog: LogCaptureFixture,
) -> None:
    """
    Parent of the parent image is not marked in the
    packages.annotations, possibly because SBOM was
    generated by konflux - we cannot determine the parent.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_edit.annotations.pop(-1)
    caplog.set_level("DEBUG")

    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    relationships = (
        await adjust_parent_image_relationship_in_legacy_sbom(
            spdx_parent_edit, grandparent_spdx_id
        )
    ).relationships
    build_tool_of_relationship = list(
        filter(
            lambda r: r.relationship_type == RelationshipType.BUILD_TOOL_OF,
            relationships,
        )
    )
    assert len(build_tool_of_relationship) == 2
    assert (
        "[Parent image content] Cannot determine parent of the downloaded parent "
        "image SBOM. It either does not exist (it was an oci-archive or the image "
        "is built from scratch) or the downloaded SBOM is not sourced from konflux."
        in caplog.messages
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_spdx_element_ids(
    spdx_parent_sbom: Document, spdx_component_sbom: Document
) -> None:
    """
    Adjusts the parent image SPDX element IDs in the legacy SBOM.
    We have component SBOM and downloaded parent image SBOM. Both
    contain SPDXRef-image as self reference. For parent SBOM it must
    be changed to name of the parent image from component SBOM to
    differ these relationships.
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    # DESCENDANT_OF relationship is already set
    # by adjust_parent_image_relationship_in_legacy_sbom_parent
    spdx_parent_edit.relationships[-1] = Relationship(
        spdx_element_id="SPDXRef-image",  # this will be changed at the end
        relationship_type=RelationshipType.DESCENDANT_OF,
        related_spdx_element_id="SPDXRef-image-registry.access.redhat.com/ubi9",
    )
    to_be_converted_parent_packages = [
        r.related_spdx_element_id
        for r in spdx_parent_edit.relationships
        if r.relationship_type == RelationshipType.CONTAINS
        and r.spdx_element_id == "SPDXRef-image"
    ]
    # SPDXRef-package_grandparent, SPDXRef-package_parent
    # in parent_sbom_legacy_with_builder.spdx.json
    assert len(to_be_converted_parent_packages) == 2

    # The component SBOM is already expected to have DESCENDANT_OF
    # relationship, because it is produced after implementation of the ISV-5858
    spdx_component_edit = deepcopy(spdx_component_sbom)
    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    adjusted_parent_sbom = await adjust_parent_image_spdx_element_ids(
        spdx_parent_edit, spdx_component_edit, grandparent_spdx_id
    )

    converted_parent_packages = [
        r.related_spdx_element_id
        for r in adjusted_parent_sbom.relationships
        if r.spdx_element_id
        == "SPDXRef-image-parent_sbom_legacy_with_builder.spdx.json"
    ]
    # SPDXRef-package_component in component_sbom.spdx.json is
    # untouched because belongs to the final component.
    # In spdxElementId it is expected to be SPDXRef-image,
    # but third SPDXRef-image-parent_sbom_legacy_with_builder.spdx.json
    # is the relationship of this parent (self) with its grandparent.
    assert len(converted_parent_packages) == 3

    # Check if the parent image's spdxElementId was
    # modified to name of the parent from component
    assert set(to_be_converted_parent_packages).issubset(set(converted_parent_packages))
    # This is the last thing that needs to be edited in parent SBOM -
    assert (
        adjusted_parent_sbom.relationships[-1].spdx_element_id
        == "SPDXRef-image-parent_sbom_legacy_with_builder.spdx.json"
    )


@pytest.mark.asyncio
async def test_adjust_parent_image_spdx_element_ids_missing_describes_relationship(
    spdx_parent_sbom: Document, spdx_component_sbom: Document
) -> None:
    """
    Downloaded parent SBOM is missing essential DESCRIBES relationship
    """
    spdx_parent_edit = deepcopy(spdx_parent_sbom)
    # DESCENDANT_OF relationship is already set
    # by adjust_parent_image_relationship_in_legacy_sbom_parent
    spdx_parent_edit.relationships.pop(0)

    # The component SBOM is already expected to have DESCENDANT_OF
    # relationship, because it is produced after implementation of the ISV-5858
    spdx_component_edit = deepcopy(spdx_component_sbom)
    grandparent_spdx_id = await get_used_parent_image_from_legacy_sbom(spdx_parent_edit)
    with pytest.raises(AssertionError):
        await adjust_parent_image_spdx_element_ids(
            spdx_parent_edit, spdx_component_edit, grandparent_spdx_id
        )


@pytest.mark.asyncio
async def test_remove_parent_image_builder_records(
    spdx_parent_sbom: Document, spdx_parent_sbom_builder_removed: Document
) -> None:
    spdx_parent_sbom_edit = deepcopy(spdx_parent_sbom)
    spdx_parent_sbom_edit = await remove_parent_image_builder_records(
        spdx_parent_sbom_edit
    )
    assert spdx_parent_sbom_edit == spdx_parent_sbom_builder_removed


@pytest.mark.asyncio
async def test_calculate_component_only_content_not_implemented() -> None:
    """Remove this after the function is implemented"""
    with pytest.raises(NotImplementedError):
        await calculate_component_only_content(MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_create_contextual_sbom_not_implemented() -> None:
    """Remove this after the function is implemented"""
    with pytest.raises(NotImplementedError):
        await create_contextual_sbom(MagicMock(), MagicMock())
