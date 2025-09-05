import datetime
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_parent_content import (
    download_parent_image_sbom,
    get_descendant_of_relationships_packages_from_used_parent,
    get_parent_spdx_id_from_component,
    get_used_parent_image_from_legacy_sbom,
)
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM


@pytest.mark.asyncio
def test_get_used_parent_image_from_legacy_sbom() -> None:
    mock_doc = MagicMock()
    base_annotation = Annotation(
        "SPDXRef-spam-parent",
        AnnotationType.OTHER,
        Actor(ActorType.TOOL, "ham"),
        datetime.datetime.now(),
        '{ "name": "konflux:container:is_base_image",   "value": "true" }',
    )
    mock_doc.annotations = [
        Annotation(
            "SPDXRef-foo",
            AnnotationType.OTHER,
            Actor(ActorType.TOOL, "bar"),
            datetime.datetime.now(),
            "le comment",
        ),
        base_annotation,
    ]
    base_package = Package("SPDXRef-spam-parent", "name", SpdxNoAssertion())
    mock_doc.packages = [
        Package("SPDXRef-spam", "name", SpdxNoAssertion()),
        base_package,
    ]
    base_relationship = Relationship(
        "SPDXRef-spam-parent", RelationshipType.BUILD_TOOL_OF, "SPDXRef-spam"
    )
    mock_doc.relationships = [base_relationship]
    pkg, annot, rel = get_used_parent_image_from_legacy_sbom(mock_doc)
    assert pkg == base_package
    assert annot == base_annotation
    assert rel == base_relationship


@pytest.mark.asyncio
def test_get_descendant_of_relationships_packages_from_used_parent_scratch_or_oci_arch(
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_doc = MagicMock()
    mock_doc.annotations = []
    mock_doc.packages = []
    mock_doc.relationships = []
    descendant_of_packages_relationships_annotations = (
        get_descendant_of_relationships_packages_from_used_parent(mock_doc, "name")
    )
    assert descendant_of_packages_relationships_annotations == []
    assert (
        "[Parent image content] Cannot determine parent of the "
        "downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch) or the downloaded SBOM is not sourced from konflux."
        in caplog.messages
    )


@pytest.mark.asyncio
def test_get_descendant_of_relationships_packages_from_used_parent_no_annot() -> None:
    mock_doc = MagicMock()
    mock_doc.annotations = []
    mock_doc.packages = [
        Package("SPDXRef-spam-parent", "name", SpdxNoAssertion()),
        Package("SPDXRef-spam", "name", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [
        Relationship(
            "SPDXRef-spam", RelationshipType.DESCENDANT_OF, "SPDXRef-spam-parent"
        )
    ]
    descendant_of_packages_relationships_annotations = (
        get_descendant_of_relationships_packages_from_used_parent(mock_doc, "name")
    )
    assert Annotation not in descendant_of_packages_relationships_annotations


@pytest.mark.asyncio
def test_get_parent_spdx_id_from_component_no_descendant_of_in_component(
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_doc = MagicMock()
    mock_doc.relationships = [
        Relationship(
            "SPDXRef-spam-parent", RelationshipType.BUILD_TOOL_OF, "SPDXRef-spam"
        )
    ]
    with pytest.raises(SBOMError):
        get_parent_spdx_id_from_component(mock_doc)


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
