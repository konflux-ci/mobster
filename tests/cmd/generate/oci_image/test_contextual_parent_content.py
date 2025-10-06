import datetime
import json
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackageVerificationCode,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_parent_content import (
    _modify_relationship_in_component,
    _supply_ancestors_from_parent_to_component,
    checksums_match,
    download_parent_image_sbom,
    generated_by_hermeto,
    get_descendant_of_items_from_used_parent,
    get_grandparent_annotation,
    get_package_purl,
    get_parent_spdx_id_from_component,
    get_relationship_by_spdx_id,
    map_parent_to_component_and_modify_component,
    package_matched,
    process_build_tool_of_grandparent_item,
    process_descendant_of_grandparent_items,
    validate_and_compare_purls,
)
from mobster.cmd.generate.oci_image.spdx_utils import get_package_by_spdx_id
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM


def get_base_image_items(
    spdx_element_id: str,
    related_spdx_element_id: str,
    legacy: bool,
    grandparent: bool = False,
) -> tuple[Package, Annotation, Relationship]:
    if legacy and grandparent:
        raise ValueError("Legacy SBOM-s does not bear grandparents.")
    if legacy:
        relationship = Relationship(
            spdx_element_id, RelationshipType.BUILD_TOOL_OF, related_spdx_element_id
        )
    else:
        # DESCENDANT_OF related_spdx_element_id and spdx_element_id
        # are intentionally swapped to create a meaningful relationship
        relationship = Relationship(
            related_spdx_element_id, RelationshipType.DESCENDANT_OF, spdx_element_id
        )
    if grandparent:
        annotation_comment = (
            '{"name": "konflux:container:was_base_image",   "value": "true" }'
        )
    else:
        annotation_comment = (
            '{"name": "konflux:container:is_base_image",   "value": "true" }'
        )
    return (
        Package(spdx_element_id, "name", SpdxNoAssertion()),
        Annotation(
            spdx_element_id,
            AnnotationType.OTHER,
            Actor(ActorType.TOOL, "ham"),
            datetime.datetime.now(),
            annotation_comment,
        ),
        relationship,
    )


def get_root_package_items() -> tuple[Package, Relationship]:
    return Package("SPDXRef-spam", "name", SpdxNoAssertion()), Relationship(
        "SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-spam"
    )


@pytest.mark.asyncio
def test_get_grandparent_from_parent_legacy_sbom() -> None:
    mock_doc = MagicMock()
    base_image_package, base_image_annotation, base_image_relationship = (
        get_base_image_items(
            spdx_element_id="SPDXRef-grandparent",
            related_spdx_element_id="SPDXRef-parent",
            legacy=True,
        )
    )
    root_package, root_relationship = get_root_package_items()
    mock_doc.annotations = [
        base_image_annotation,
    ]
    mock_doc.packages = [
        base_image_package,
        root_package,
    ]
    mock_doc.relationships = [base_image_relationship]
    annot = get_grandparent_annotation(mock_doc)

    assert annot is not None
    pkg = get_package_by_spdx_id(mock_doc, annot.spdx_id)
    rel = get_relationship_by_spdx_id(
        mock_doc,
        annot.spdx_id,
        expected_relationship_type=RelationshipType.BUILD_TOOL_OF,
    )
    assert pkg == base_image_package
    assert annot == base_image_annotation
    assert rel == base_image_relationship


@pytest.mark.asyncio
def test_get_grandparent_from_contextualized_parent_sbom() -> None:
    mock_doc = MagicMock()
    (
        grandparent_image_package,
        grandparent_image_annotation,
        grandparent_image_relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-grandgrandparent",
        related_spdx_element_id="SPDXRef-grandparent",
        legacy=False,
        grandparent=True,
    )
    parent_image_package, parent_image_annotation, parent_image_relationship = (
        get_base_image_items(
            spdx_element_id="SPDXRef-grandparent",
            related_spdx_element_id="SPDXRef-parent",
            legacy=False,
        )
    )
    root_package, root_relationship = get_root_package_items()
    mock_doc.annotations = [
        grandparent_image_annotation,
        parent_image_annotation,
    ]
    mock_doc.packages = [
        grandparent_image_package,
        parent_image_package,
        root_package,
    ]
    mock_doc.relationships = [
        grandparent_image_relationship,
        parent_image_relationship,
        root_relationship,
    ]
    annot = get_grandparent_annotation(mock_doc)

    assert annot is not None
    pkg = get_package_by_spdx_id(mock_doc, annot.spdx_id)
    rel = get_relationship_by_spdx_id(
        mock_doc,
        annot.spdx_id,
        expected_relationship_type=RelationshipType.DESCENDANT_OF,
    )
    assert pkg == parent_image_package
    assert annot == parent_image_annotation
    assert rel == parent_image_relationship


def test_annotation_parse_fail(
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_doc = MagicMock()
    mock_doc.annotations = [
        Annotation(
            "invalid_annotation",
            AnnotationType.OTHER,
            Actor(ActorType.TOOL, "ham"),
            datetime.datetime.now(),
            "unexpected comment",
        ),
    ]

    get_grandparent_annotation(mock_doc)
    assert (
        "Annotation comment 'unexpected comment' is not in JSON format."
        in caplog.messages
    )


def test_get_descendant_of_items_from_used_parent_scratch_or_oci_arch(
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_doc = MagicMock()
    mock_doc.annotations = []
    mock_doc.packages = []
    mock_doc.relationships = []
    get_descendant_of_items_from_used_parent(mock_doc, "name")
    assert (
        "[Parent image content] Cannot determine parent of the downloaded "
        "parent image SBOM. It either does not exist (it was an oci-archive "
        "or the image is built from scratch), it is malformed or the downloaded "
        "SBOMis not sourced from konflux." in caplog.messages
    )


def test_get_descendant_of_items_from_used_parent_invalid_sbom_structure(
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_doc = MagicMock()
    mock_doc.creation_info.name = (
        "quay.io/test-org-cat-feeder/user-ns2/testrepo-giver@sha256:1"
    )
    (
        package,
        annotation,
        relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-spam-grandparent",
        related_spdx_element_id="SPDXRef-parent",
        legacy=False,
    )
    mock_doc.annotations = [
        annotation,
    ]
    mock_doc.packages = []
    mock_doc.relationships = []
    assert get_descendant_of_items_from_used_parent(mock_doc, "name") == []
    assert (
        "No package found for annotation SPDXRef-spam-grandparent in downloaded parent "
        "SBOM quay.io/test-org-cat-feeder/user-ns2/testrepo-giver@sha256:1"
    ) in caplog.messages

    mock_doc.packages = [package]

    assert get_descendant_of_items_from_used_parent(mock_doc, "name") == []
    assert (
        "No BUILD_TOOL_OF relationship found for package SPDXRef-spam-grandparent "
        "in downloaded parent SBOM "
        "quay.io/test-org-cat-feeder/user-ns2/testrepo-giver@sha256:1"
    ) in caplog.messages


@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.process_build_tool_of_grandparent_item"
)
def test_get_descendant_of_items_from_used_parent_ancestor_is_legacy(
    mock_process_build_tool_of_grandparent_item: MagicMock,
) -> None:
    mock_doc = MagicMock()
    (
        grandparent_package,
        grandparent_annotation,
        grandparent_relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-grandparent",
        related_spdx_element_id="SPDXRef-parent",
        legacy=True,
    )
    mock_doc.annotations = [
        grandparent_annotation,
    ]
    mock_doc.packages = [grandparent_package]
    mock_doc.relationships = [grandparent_relationship]
    get_descendant_of_items_from_used_parent(mock_doc, "parent_spdx_id_from_component")
    mock_process_build_tool_of_grandparent_item.assert_called_once_with(
        grandparent_package,
        grandparent_annotation,
        grandparent_relationship,
        "parent_spdx_id_from_component",
    )


@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.process_descendant_of_grandparent_items"
)
def test_get_descendant_of_items_from_used_parent_ancestor_is_contextual(
    mock_process_descendant_of_grandparent_items: MagicMock,
) -> None:
    mock_doc = MagicMock()
    (
        grandparent_package,
        grandparent_annotation,
        grandparent_relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-grandparent",
        related_spdx_element_id="SPDXRef-parent",
        legacy=False,
    )
    mock_doc.annotations = [
        grandparent_annotation,
    ]
    mock_doc.packages = [grandparent_package]
    mock_doc.relationships = [grandparent_relationship]
    get_descendant_of_items_from_used_parent(mock_doc, "parent_spdx_id_from_component")
    mock_process_descendant_of_grandparent_items.assert_called_once_with(
        mock_doc,
        grandparent_package,
        "parent_spdx_id_from_component",
        [(grandparent_package, grandparent_relationship)],
    )


@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.process_descendant_of_grandparent_items"
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.process_build_tool_of_grandparent_item"
)
def test_get_descendant_of_items_from_used_parent_grandparent_has_no_annot(
    mock_process_build_tool_of_grandparent_item: MagicMock,
    mock_process_descendant_of_grandparent_items: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    mock_doc = MagicMock()

    mock_doc.annotations = []  # missing
    mock_doc.packages = [
        Package("SPDXRef-grandparent", "name", SpdxNoAssertion()),
        Package("SPDXRef-parent", "name", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [
        Relationship(
            "SPDXRef-parent", RelationshipType.DESCENDANT_OF, "SPDXRef-grandparent"
        )
    ]
    descendant_of_items = get_descendant_of_items_from_used_parent(mock_doc, "name")
    assert len(descendant_of_items) == 0
    mock_process_build_tool_of_grandparent_item.assert_not_called()
    mock_process_descendant_of_grandparent_items.assert_not_called()
    assert (
        "[Parent image content] Cannot determine parent of the "
        "downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch), it is malformed or the downloaded SBOM"
        "is not sourced from konflux." in caplog.messages
    )


def test_process_descendant_of_grandparent_items_missing_annot(
    caplog: LogCaptureFixture,
) -> None:
    mock_doc = MagicMock()
    (
        grandparent_image_package,
        grandparent_image_annotation,
        grandparent_image_relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-grandgrandparent",
        related_spdx_element_id="SPDXRef-grandparent",
        legacy=False,
        grandparent=True,
    )
    parent_image_package, parent_image_annotation, parent_image_relationship = (
        get_base_image_items(
            spdx_element_id="SPDXRef-grandparent",
            related_spdx_element_id="SPDXRef-parent",
            legacy=False,
        )
    )
    root_package, root_relationship = get_root_package_items()

    mock_doc.packages = [
        grandparent_image_package,
        parent_image_package,
        root_package,
    ]
    mock_doc.relationships = [
        grandparent_image_relationship,
        parent_image_relationship,
        root_relationship,
    ]
    mock_doc.annotations = [parent_image_annotation]

    process_descendant_of_grandparent_items(
        mock_doc,
        grandparent_image_package,
        "parent_name_from_component",
        [
            (grandparent_image_package, grandparent_image_relationship),
            (parent_image_package, parent_image_relationship),
        ],
    )
    assert "Annotation not found for SPDXRef-grandgrandparent" in caplog.messages


def test_get_parent_spdx_id_from_component() -> None:
    mock_doc = MagicMock()
    mock_doc.relationships = [
        Relationship(
            "SPDXRef-component",
            RelationshipType.DESCENDANT_OF,
            "SPDXRef-parent-name-from-component",
        )
    ]
    assert "SPDXRef-parent-name-from-component" == get_parent_spdx_id_from_component(
        mock_doc
    )


def test_process_build_tool_of_grandparent_item() -> None:
    (
        grandparent_image_package,
        grandparent_image_annotation,
        grandparent_image_relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-grandparent",
        related_spdx_element_id="SPDXRef-parent",
        legacy=True,
    )

    expected_relationship = Relationship(
        "SPDXRef-spam-parent-name-from-component",
        RelationshipType.DESCENDANT_OF,
        "SPDXRef-grandparent",
    )
    relationship = process_build_tool_of_grandparent_item(
        grandparent_image_package,
        grandparent_image_annotation,
        grandparent_image_relationship,
        parent_spdx_id_from_component="SPDXRef-spam-parent-name-from-component",
    )[0][1]  # returns list of items (package, relationship,
    # annotation) - we are interested in relationship
    assert expected_relationship == relationship


@pytest.mark.asyncio
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content._supply_ancestors_from_parent_to_component"
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content._modify_relationship_in_component"
)
@patch("mobster.cmd.generate.oci_image.contextual_parent_content.package_matched")
async def test_map_parent_to_component_and_modify_component(
    mock_package_matched: MagicMock,
    mock__modify_relationship_in_component: MagicMock,
    mock__supply_ancestors_from_parent_to_component: MagicMock,
) -> None:
    parent_sbom_doc = MagicMock()
    component_sbom_doc = MagicMock()
    parent_spdx_id_from_component = "SPDXRef-parent-name-from-component"

    (
        grandparent_image_package,
        grandparent_image_annotation,
        grandparent_image_relationship,
    ) = get_base_image_items(
        spdx_element_id="SPDXRef-grandgrandparent",
        related_spdx_element_id="SPDXRef-grandparent",
        legacy=False,
        grandparent=True,
    )
    parent_image_package, parent_image_annotation, parent_image_relationship = (
        get_base_image_items(
            spdx_element_id="SPDXRef-grandparent",
            related_spdx_element_id="SPDXRef-parent",
            legacy=False,
        )
    )
    root_package, root_relationship = get_root_package_items()

    parent_sbom_doc.packages = [
        grandparent_image_package,
        parent_image_package,
        root_package,
        Package("SPDXRef-package-1", "package", SpdxNoAssertion()),
    ]
    parent_package_relationship = Relationship(
        "SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-package-1"
    )
    parent_sbom_doc.relationships = [
        grandparent_image_relationship,
        parent_image_relationship,
        root_relationship,
        parent_package_relationship,
    ]
    parent_sbom_doc.annotations = [
        parent_image_annotation,
        grandparent_image_annotation,
    ]

    component_matched_package = Package(
        "SPDXRef-package-1", "package", SpdxNoAssertion()
    )
    component_sbom_doc.packages = [
        component_matched_package,
    ]
    modified_relationship = Relationship(
        "SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-package-1"
    )
    component_sbom_doc.relationships = [
        modified_relationship,
    ]
    mock_package_matched.return_value = True
    descendant_of_items_from_used_parent = [
        (
            grandparent_image_package,
            grandparent_image_relationship,
            grandparent_image_annotation,
        ),
        (parent_image_package, parent_image_relationship, parent_image_annotation),
    ]
    await map_parent_to_component_and_modify_component(
        parent_sbom_doc,
        component_sbom_doc,
        parent_spdx_id_from_component,
        descendant_of_items_from_used_parent,
    )
    mock__modify_relationship_in_component.assert_called_once_with(
        modified_relationship,
        parent_package_relationship,
        parent_spdx_id_from_component,
        [root_package.spdx_id],
    )
    mock__supply_ancestors_from_parent_to_component.assert_called_once_with(
        component_sbom_doc, descendant_of_items_from_used_parent
    )


def test__supply_ancestors_from_parent_to_component() -> None:
    component_sbom_doc = MagicMock()
    component_sbom_doc.packages = []
    component_sbom_doc.annotations = []
    component_sbom_doc.relationships = []

    grandparent_package, grandparent_annotation, grandparent_relationship = (
        get_base_image_items(
            spdx_element_id="SPDXRef-grandparent",
            related_spdx_element_id="SPDXRef-parent",
            legacy=False,
            grandparent=True,
        )
    )
    descendant_of_items_from_used_parent = [
        (
            grandparent_package,
            grandparent_relationship,
            grandparent_annotation,
        ),
    ]

    result = _supply_ancestors_from_parent_to_component(
        component_sbom_doc, descendant_of_items_from_used_parent
    )
    assert grandparent_package in result.packages
    assert (
        result.annotations[0].annotation_comment
        == '{"name": "konflux:container:was_base_image",   "value": "true" }'
    )
    assert grandparent_relationship in result.relationships


@pytest.mark.parametrize(
    [
        "component_relationship",
        "parent_relationship",
        "parent_spdx_id_from_component",
        "parent_root_packages",
        "result",
    ],
    [
        pytest.param(
            Relationship("SPDXRef-component", RelationshipType.CONTAINS, "package"),
            Relationship("SPDXRef-parent", RelationshipType.CONTAINS, "package"),
            "SPDXRef-parent-name-from-component",
            ["SPDXRef-parent"],
            Relationship(
                "SPDXRef-parent-name-from-component",
                RelationshipType.CONTAINS,
                "package",
            ),
            id="Parent relationship indicates that package belongs"
            "to parent itself - parent in component relationship"
            "must be renamed according to the name of the parent"
            "in component.",
        ),
        pytest.param(
            Relationship("SPDXRef-component", RelationshipType.CONTAINS, "package"),
            Relationship("SPDXRef-grandparent", RelationshipType.CONTAINS, "package"),
            "SPDXRef-parent-name-from-component",
            ["SPDXRef-parent"],
            Relationship("SPDXRef-grandparent", RelationshipType.CONTAINS, "package"),
            id="Parent relationship is result of contextualization"
            "and must be copied to component.",
        ),
    ],
)
def test__modify_relationship_in_component(
    component_relationship: Relationship,
    parent_relationship: Relationship,
    parent_spdx_id_from_component: str,
    parent_root_packages: list[str],
    result: Relationship,
) -> None:
    _modify_relationship_in_component(
        component_relationship,
        parent_relationship,
        parent_spdx_id_from_component,
        parent_root_packages,
    )

    assert component_relationship == result


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


@pytest.mark.parametrize(
    ["annotations", "expected_result"],
    [
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "cachi2"),
                    datetime.datetime.now(),
                    '{"name": "cachi2:found_by", "value": "cachi2"}',
                ),
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "other-tool"),
                    datetime.datetime.now(),
                    '{"name": "other-tool:found_by", "value": "other-tool"}',
                ),
            ],
            True,
            id="cachi2-detection",
        ),
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "hermeto"),
                    datetime.datetime.now(),
                    '{"name": "hermeto:found_by", "value": "hermeto"}',
                ),
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "other-tool"),
                    datetime.datetime.now(),
                    '{"name": "other-tool:found_by", "value": "other-tool"}',
                ),
            ],
            True,
            id="hermeto-detection",
        ),
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "other-tool"),
                    datetime.datetime.now(),
                    '{"name": "other-tool:found_by", "value": "other-tool"}',
                ),
            ],
            False,
            id="non-hermeto-detection",
        ),
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.PERSON, "user"),
                    datetime.datetime.now(),
                    '{"name": "cachi2:found_by", "value": "cachi2"}',
                ),
            ],
            False,
            id="wrong-actor-type",
        ),
        pytest.param(
            [],
            False,
            id="empty-annotations",
        ),
    ],
)
def test_generated_by_hermeto(
    annotations: list[Annotation], expected_result: bool
) -> None:
    assert generated_by_hermeto(annotations) is expected_result


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


@pytest.mark.parametrize(
    ["component_purl", "parent_purl", "expected_result"],
    [
        # Successful validation, required fields and namespace match, qualifiers ignored
        pytest.param(
            "pkg:npm/test-namespace/test-package@1.0.0?arch=amd64&distro=fedora&os=linux&checksum=sha256:abc123",
            "pkg:npm/test-namespace/test-package@1.0.0?arch=x86_64&distro=ubuntu&os=linux&checksum=sha256:def456",
            True,
            id="successful-validation",
        ),
        pytest.param(
            "pkg:npm/test-namespace/test-package@1.0.0",
            "pkg:npm/test-package@1.0.0",
            False,
            id="namespace-missing",
        ),
        pytest.param(
            "pkg:npm/test-namespace/test-package@1.0.0",
            "pkg:npm/different-namespace/test-package@1.0.0",
            False,
            id="namespace-mismatch",
        ),
        pytest.param(
            "invalid-purl", "pkg:npm/test-package@1.0.0", False, id="invalid-format"
        ),
        pytest.param(
            "pkg:npm@1.0.0", "pkg:npm/test-package@1.0.0", False, id="missing-name"
        ),
        pytest.param(
            "pkg:npm/test-package",
            "pkg:npm/test-package@1.0.0",
            False,
            id="missing-version",
        ),
        pytest.param("", "pkg:npm/test-package@1.0.0", False, id="empty-string-one"),
        pytest.param("", "", False, id="empty-string-both"),
        pytest.param(
            None, "pkg:npm/test-package@1.0.0", False, id="none-component-purl"
        ),
        pytest.param("pkg:npm/test-package@1.0.0", None, False, id="none-parent-purl"),
        pytest.param(None, None, False, id="none-both"),
    ],
)
def test_validate_and_compare_purls(
    component_purl: str, parent_purl: str, expected_result: bool
) -> None:
    assert validate_and_compare_purls(component_purl, parent_purl) == expected_result


@pytest.mark.parametrize(
    ["parent_checksums", "component_checksums", "expected_result"],
    [
        # Successful matches for all checksums
        pytest.param(
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA256, "xyz789"),
            ],
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA256, "xyz789"),
            ],
            True,
            id="successful-matches",
        ),
        pytest.param(
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA1, "xyz789"),
            ],
            [
                Checksum(ChecksumAlgorithm.SHA256, "different123"),
                Checksum(ChecksumAlgorithm.MD5, "different456"),
            ],
            False,
            id="no-matches",
        ),
        pytest.param(
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA1, "xyz789"),
            ],
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA1, "xyz789"),
                Checksum(ChecksumAlgorithm.MD5, "different"),
            ],
            False,
            id="some-common-items-but-not-all-match",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [],
            False,
            id="one-empty-list",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA1, "abc123def456")],
            False,
            id="different-algorithms-same-value",
        ),
    ],
)
def test_checksums_match(
    parent_checksums: list[Checksum],
    component_checksums: list[Checksum],
    expected_result: bool,
) -> None:
    assert checksums_match(parent_checksums, component_checksums) is expected_result


@pytest.mark.parametrize(
    ["purls_match", "expected_result"],
    [
        (True, True),
        (False, False),
    ],
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.get_annotations_by_spdx_id"
)
@patch("mobster.cmd.generate.oci_image.contextual_parent_content.get_package_purl")
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.validate_and_compare_purls"
)
@patch("mobster.cmd.generate.oci_image.contextual_parent_content.generated_by_hermeto")
def test_package_matched_hermeto_to_syft(
    mock_generated_by_hermeto: MagicMock,
    mock_validate_and_compare_purls: MagicMock,
    mock_get_package_purl: MagicMock,
    mock_get_annotations_by_spdx_id: MagicMock,
    purls_match: bool,
    expected_result: bool,
) -> None:
    """Test package matching for hermeto-generated packages."""
    mock_validate_and_compare_purls.return_value = purls_match
    mock_generated_by_hermeto.return_value = True

    parent_doc = MagicMock(spec=Document)
    parent_package = MagicMock(spec=Package)
    component_package = MagicMock(spec=Package)

    result = package_matched(parent_doc, parent_package, component_package)

    mock_get_annotations_by_spdx_id.assert_called_once_with(
        parent_doc, parent_package.spdx_id
    )
    mock_get_package_purl.assert_has_calls(
        [
            call(parent_package),
            call(component_package),
        ]
    )
    mock_validate_and_compare_purls.assert_called_once()
    mock_generated_by_hermeto.assert_called_once()

    assert result is expected_result


@pytest.mark.parametrize(
    [
        "parent_checksums",
        "component_checksums",
        "parent_verification_code",
        "component_verification_code",
        "purls_match",
        "expected_result",
    ],
    [
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            PackageVerificationCode(value="abc123"),
            PackageVerificationCode(value="different123"),
            False,
            True,
            id="checksums-match-others-mismatch",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            None,
            None,
            False,
            True,
            id="checksums-match-others-missing",
        ),
        pytest.param(
            [],
            [],
            PackageVerificationCode(value="abc123"),
            PackageVerificationCode(value="abc123"),
            False,
            True,
            id="only-verification-codes-match",
        ),
        pytest.param(
            [],
            [],
            None,
            None,
            True,
            True,
            id="only-purls-match",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA256, "different123def456")],
            PackageVerificationCode(value="abc123"),
            PackageVerificationCode(value="abc123"),
            True,
            False,
            id="checksums-mismatch-others-match",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [],
            PackageVerificationCode(value="abc123"),
            None,
            True,
            False,
            id="one-checksum-and-one-verification-code-missing-purls-match",
        ),
        pytest.param(
            [],
            [],
            None,
            None,
            False,
            False,
            id="checksums-and-verification-codes-missing-purls-mismatch",
        ),
    ],
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.get_annotations_by_spdx_id"
)
@patch("mobster.cmd.generate.oci_image.contextual_parent_content.get_package_purl")
@patch(
    "mobster.cmd.generate.oci_image.contextual_parent_content.validate_and_compare_purls"
)
@patch("mobster.cmd.generate.oci_image.contextual_parent_content.generated_by_hermeto")
def test_package_matched_syft_to_syft(
    mock_generated_by_hermeto: MagicMock,
    mock_validate_and_compare_purls: MagicMock,
    mock_get_package_purl: MagicMock,
    mock_get_annotations_by_spdx_id: MagicMock,
    parent_checksums: list[Checksum],
    component_checksums: list[Checksum],
    parent_verification_code: PackageVerificationCode,
    component_verification_code: PackageVerificationCode,
    purls_match: bool,
    expected_result: bool,
) -> None:
    mock_validate_and_compare_purls.return_value = purls_match
    mock_generated_by_hermeto.return_value = False

    parent_doc = MagicMock(spec=Document)
    parent_package = MagicMock(spec=Package)
    parent_package.checksums = parent_checksums
    parent_package.verification_code = parent_verification_code
    component_package = MagicMock(spec=Package)
    component_package.checksums = component_checksums
    component_package.verification_code = component_verification_code

    result = package_matched(parent_doc, parent_package, component_package)

    mock_get_package_purl.assert_has_calls(
        [
            call(parent_package),
            call(component_package),
        ]
    )
    mock_generated_by_hermeto.assert_called_once()

    assert result is expected_result
