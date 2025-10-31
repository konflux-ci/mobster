import datetime
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_sbom.contextualize import (
    _modify_relationship_in_component,
    _supply_ancestors_from_parent_to_component,
    download_parent_image_sbom,
    get_descendant_of_items_from_used_parent,
    get_grandparent_annotation,
    get_parent_spdx_id_from_component,
    get_relationship_by_spdx_id,
    map_parent_to_component_and_modify_component,
    process_build_tool_of_grandparent_item,
    process_descendant_of_grandparent_items,
)
from mobster.cmd.generate.oci_image.spdx_utils import get_package_by_spdx_id
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM

from .conftest import (
    create_package_with_identifier,
    get_base_image_items,
    get_root_package_items,
)


@pytest.mark.asyncio
def test_get_grandparent_from_parent_legacy_sbom(mock_doc: MagicMock) -> None:
    base_image_package, base_image_annotation, base_image_relationship = (
        get_base_image_items(
            spdx_element_id="SPDXRef-grandparent",
            related_spdx_element_id="SPDXRef-parent",
            legacy=True,
        )
    )
    root_package, root_relationship = get_root_package_items("SPDXRef-parent")
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
def test_get_grandparent_from_contextualized_parent_sbom(mock_doc: MagicMock) -> None:
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
    root_package, root_relationship = get_root_package_items("SPDXRef-parent")
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
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
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
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
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
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
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
    "mobster.cmd.generate.oci_image.contextual_sbom.contextualize.process_build_tool_of_grandparent_item"
)
def test_get_descendant_of_items_from_used_parent_ancestor_is_legacy(
    mock_process_build_tool_of_grandparent_item: MagicMock,
    mock_doc: MagicMock,
) -> None:
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
    "mobster.cmd.generate.oci_image.contextual_sbom.contextualize.process_descendant_of_grandparent_items"
)
def test_get_descendant_of_items_from_used_parent_ancestor_is_contextual(
    mock_process_descendant_of_grandparent_items: MagicMock,
    mock_doc: MagicMock,
) -> None:
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
    "mobster.cmd.generate.oci_image.contextual_sbom.contextualize.process_descendant_of_grandparent_items"
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.contextualize.process_build_tool_of_grandparent_item"
)
def test_get_descendant_of_items_from_used_parent_grandparent_has_no_annot(
    mock_process_build_tool_of_grandparent_item: MagicMock,
    mock_process_descendant_of_grandparent_items: MagicMock,
    caplog: LogCaptureFixture,
    mock_doc: MagicMock,
) -> None:
    caplog.set_level("DEBUG")

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
    mock_doc: MagicMock,
) -> None:
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
    root_package, root_relationship = get_root_package_items("SPDXRef-parent")

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


def test_get_parent_spdx_id_from_component(mock_doc: MagicMock) -> None:
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
    _, relationship, _ = process_build_tool_of_grandparent_item(
        grandparent_image_package,
        grandparent_image_annotation,
        grandparent_image_relationship,
        parent_spdx_id_from_component="SPDXRef-spam-parent-name-from-component",
    )[0]
    assert expected_relationship == relationship


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["identifier_type", "should_match"],
    [
        ("checksum", True),
        ("checksum", False),
        ("verification_code", True),
        ("verification_code", False),
        ("purl", True),
        ("purl", False),
    ],
)
async def test_map_parent_to_component_and_modify_component(
    identifier_type: str,
    should_match: bool,
) -> None:
    """
    Test package matching via ComponentPackageIndex using different identifier types.

    Verifies that:
    1. Index finds packages by checksum, verification_code, or purl
    2. Matching packages -> relationship modified to use parent SPDX ID
    3. Non-matching packages -> relationship unchanged
    4. Ancestor packages/relationships always added
    """
    parent_spdx_id = "SPDXRef-parent-name-from-component"

    # Setup parent SBOM with grandparent and test package
    parent_sbom_doc = MagicMock(spec=Document)
    grandparent_pkg, grandparent_annot, grandparent_rel = get_base_image_items(
        "SPDXRef-grandparent", "SPDXRef-parent", legacy=False
    )
    root_pkg, root_rel = get_root_package_items("SPDXRef-parent")
    parent_test_pkg = create_package_with_identifier(
        "SPDXRef-package-1", identifier_type
    )

    parent_sbom_doc.packages = [grandparent_pkg, root_pkg, parent_test_pkg]
    parent_sbom_doc.relationships = [
        grandparent_rel,
        root_rel,
        Relationship("SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-package-1"),
    ]
    parent_sbom_doc.annotations = [grandparent_annot]

    # Setup component SBOM with matching/non-matching package
    component_sbom_doc = MagicMock(spec=Document)
    component_img_pkg, component_annot, component_rel = get_base_image_items(
        parent_spdx_id, "SPDXRef-component", legacy=False
    )
    component_test_pkg = create_package_with_identifier(
        "SPDXRef-package-1", identifier_type, matching_value=should_match
    )

    original_rel = Relationship(
        "SPDXRef-component", RelationshipType.CONTAINS, "SPDXRef-package-1"
    )
    component_sbom_doc.packages = [component_img_pkg, component_test_pkg]
    component_sbom_doc.relationships = [component_rel, original_rel]
    component_sbom_doc.annotations = [component_annot]

    # Execute contextualization
    result = await map_parent_to_component_and_modify_component(
        parent_sbom_doc,
        component_sbom_doc,
        parent_spdx_id,
        [(grandparent_pkg, grandparent_rel, grandparent_annot)],
    )

    # Verify relationship modification
    contains_rels = [
        r
        for r in result.relationships
        if r.relationship_type == RelationshipType.CONTAINS
    ]
    if should_match:
        assert any(r.spdx_element_id == parent_spdx_id for r in contains_rels), (
            f"Matching {identifier_type}: relationship should bear {parent_spdx_id}"
        )
    else:
        assert original_rel in result.relationships, (
            f"Non-matching {identifier_type}: original relationship should remain"
        )

    # Verify ancestors always added from parent
    assert grandparent_pkg in result.packages
    assert grandparent_rel in result.relationships
    assert any("is_ancestor_image" in a.annotation_comment for a in result.annotations)


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.contextual_sbom.contextualize.package_matched")
async def test_skip_already_matched_component_package(
    mock_package_matched: MagicMock,
) -> None:
    """
    Test that already matched component packages are skipped.
    When parent contains duplicate packages (packages with same "unique" id)
    package_matched() should be called only once.
    The second parent package finds the same
    candidate but skips it because it's already matched.
    """
    shared_checksum = Checksum(ChecksumAlgorithm.SHA256, "duplicate123")
    parent_spdx_id = "SPDXRef-parent-from-component"

    # Parent SBOM: 2 duplicate packages with same checksum
    parent_sbom_doc = MagicMock(spec=Document)
    parent_root = Package("SPDXRef-parent", "parent", SpdxNoAssertion())
    parent_pkg_1 = Package(
        "SPDXRef-p1", "duplicate-pkg", SpdxNoAssertion(), checksums=[shared_checksum]
    )
    parent_pkg_2 = Package(
        "SPDXRef-p2", "duplicate-pkg", SpdxNoAssertion(), checksums=[shared_checksum]
    )

    parent_sbom_doc.packages = [parent_root, parent_pkg_1, parent_pkg_2]
    parent_sbom_doc.relationships = [
        Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-parent"),
        Relationship("SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-p1"),
        Relationship("SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-p2"),
    ]
    parent_sbom_doc.annotations = []

    # Component SBOM: 1 package with matching checksum
    component_sbom_doc = MagicMock(spec=Document)
    component_root = Package("SPDXRef-component", "component", SpdxNoAssertion())
    component_pkg = Package(
        "SPDXRef-c1", "duplicate-pkg", SpdxNoAssertion(), checksums=[shared_checksum]
    )

    component_sbom_doc.packages = [component_root, component_pkg]
    component_sbom_doc.relationships = [
        Relationship(
            "SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-component"
        ),
        Relationship(
            "SPDXRef-component", RelationshipType.DESCENDANT_OF, parent_spdx_id
        ),
        Relationship("SPDXRef-component", RelationshipType.CONTAINS, "SPDXRef-c1"),
    ]
    component_sbom_doc.annotations = []

    mock_package_matched.return_value = True
    await map_parent_to_component_and_modify_component(
        parent_sbom_doc, component_sbom_doc, parent_spdx_id, []
    )

    assert mock_package_matched.call_count == 1, (
        f"Expected package_matched called 1 time, "
        f"got {mock_package_matched.call_count}. "
    )


def test__supply_ancestors_from_parent_to_component() -> None:
    component_sbom_doc = MagicMock(spec=Document)
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
        == '{"name": "konflux:container:is_ancestor_image",   "value": "true" }'
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
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
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
