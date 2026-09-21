import datetime
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    ANCESTOR_IMAGE,
    BASE_IMAGE,
    LEGACY_BASE_IMAGE,
    ContentKind,
)
from mobster.cmd.generate.oci_image.contextual_sbom.logging import (
    MatchingStatistics,
)
from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    ComponentRelationshipResolver,
)
from mobster.cmd.generate.oci_image.contextual_sbom.parent import (
    ImageItem,
    collect_image_items,
    collect_package_items,
    download_parent_image_sbom,
    get_annotation_by_spdx_id_filter_by_type,
    get_grandparent_and_ancestor_items_from_used_parent,
    get_parent_spdx_id_from_component,
    map_parent_to_component_and_update_component,
    process_grandparent_item,
)
from mobster.cmd.generate.oci_image.spdx_utils import (
    KONFLUX_JSON_ACTOR,
    AnnotationAncestorImage,
    AnnotationBaseImage,
    KonfluxAnnotationManager,
)
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM

from .conftest import (
    create_package_with_identifier,
    get_root_package_items,
)


def _content_item(owner_id: str, pkg_id: str) -> tuple[Package, Relationship]:
    """`owner CONTAINS pkg` content-package item."""
    pkg = Package(pkg_id, "name", SpdxNoAssertion())
    rel = Relationship(owner_id, RelationshipType.CONTAINS, pkg_id)
    return pkg, rel


def _base_image_item(
    parent_id: str, grandparent_id: str
) -> tuple[Package, Relationship, Annotation]:
    """`parent DESCENDANT_OF grandparent`, grandparent annotated is_base_image."""
    pkg = Package(grandparent_id, "name", SpdxNoAssertion())
    rel = Relationship(parent_id, RelationshipType.DESCENDANT_OF, grandparent_id)
    annot = KonfluxAnnotationManager.base_image(grandparent_id)
    return pkg, rel, annot


def _ancestor_image_item(
    child_id: str, ancestor_id: str
) -> tuple[Package, Relationship, Annotation]:
    """`child DESCENDANT_OF ancestor`, ancestor annotated is_ancestor_image."""
    pkg = Package(ancestor_id, "name", SpdxNoAssertion())
    rel = Relationship(child_id, RelationshipType.DESCENDANT_OF, ancestor_id)
    annot = KonfluxAnnotationManager.ancestor_image(ancestor_id)
    return pkg, rel, annot


def _legacy_grandparent_item(
    grandparent_id: str, parent_id: str
) -> tuple[Package, Relationship, Annotation]:
    """Legacy `grandparent BUILD_TOOL_OF parent`, annotated is_base_image."""
    pkg = Package(grandparent_id, "name", SpdxNoAssertion())
    rel = Relationship(grandparent_id, RelationshipType.BUILD_TOOL_OF, parent_id)
    annot = KonfluxAnnotationManager.base_image(grandparent_id)
    return pkg, rel, annot


def test_collect_package_items(mock_doc: MagicMock) -> None:
    pkg1, rel1 = _content_item("SPDXRef-root", "SPDXRef-pkg1")
    pkg2, rel2 = _content_item("SPDXRef-root", "SPDXRef-pkg2")
    mock_doc.packages = [pkg1, pkg2]
    mock_doc.relationships = [rel1, rel2]

    assert collect_package_items(mock_doc) == [(pkg1, rel1), (pkg2, rel2)]


def test_collect_package_items_skips_package_without_contains(
    mock_doc: MagicMock,
) -> None:
    pkg1, rel1 = _content_item("SPDXRef-root", "SPDXRef-pkg1")
    orphan = Package("SPDXRef-orphan", "name", SpdxNoAssertion())
    mock_doc.packages = [pkg1, orphan]
    mock_doc.relationships = [rel1]

    assert collect_package_items(mock_doc) == [(pkg1, rel1)]


def test_collect_package_items_raises_on_duplicate_relationship(
    mock_doc: MagicMock,
) -> None:
    """A content package must have exactly one CONTAINS relationship."""
    pkg, rel = _content_item("SPDXRef-root", "SPDXRef-pkg")
    duplicate_rel = Relationship(
        "SPDXRef-other-root", RelationshipType.CONTAINS, pkg.spdx_id
    )
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel, duplicate_rel]

    with pytest.raises(
        SBOMError,
        match=(
            r"Multiple relationships found for content kind 'content package' "
            r"\(CONTAINS, related_spdx_element_id\) and SPDX ID "
            r"'SPDXRef-pkg'\."
        ),
    ):
        collect_package_items(mock_doc)


@pytest.mark.parametrize(
    ("kind", "item"),
    [
        pytest.param(
            BASE_IMAGE,
            _base_image_item("SPDXRef-parent", "SPDXRef-grandparent"),
            id="parent-base-image",
        ),
        pytest.param(
            ANCESTOR_IMAGE,
            _ancestor_image_item("SPDXRef-grandparent", "SPDXRef-ancestor"),
            id="parent-ancestor-image",
        ),
    ],
)
def test_collect_image_items_by_content_kind(
    mock_doc: MagicMock,
    kind: ContentKind,
    item: tuple[Package, Relationship, Annotation],
) -> None:
    pkg, rel, annot = item
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, kind) == [ImageItem(pkg, rel, annot)]


def test_collect_image_items_legacy_grandparent(mock_doc: MagicMock) -> None:
    pkg, rel, annot = _legacy_grandparent_item("SPDXRef-grandparent", "SPDXRef-parent")
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, LEGACY_BASE_IMAGE) == [
        ImageItem(pkg, rel, annot)
    ]


def test_collect_image_items_raises_on_duplicate_relationship(
    mock_doc: MagicMock,
) -> None:
    """A base image package must not have multiple relevant relationships."""
    pkg, rel, annot = _base_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    duplicate_rel = Relationship(
        "SPDXRef-other-parent",
        RelationshipType.DESCENDANT_OF,
        pkg.spdx_id,
    )
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel, duplicate_rel]
    mock_doc.annotations = [annot]

    with pytest.raises(
        SBOMError,
        match=(
            r"Multiple relationships found for content kind 'base image' "
            r"\(DESCENDANT_OF, related_spdx_element_id\) and SPDX ID "
            r"'SPDXRef-grandparent'\."
        ),
    ):
        collect_image_items(mock_doc, BASE_IMAGE)


def test_collect_image_items_skips_missing_annotation(mock_doc: MagicMock) -> None:
    """
    Image package + relationship are present,
    but no annotation to disambiguate the kind
    """
    pkg, rel, _ = _base_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel]
    mock_doc.annotations = []

    assert collect_image_items(mock_doc, BASE_IMAGE) == []


def test_collect_image_items_skips_missing_relationship(mock_doc: MagicMock) -> None:
    """
    Annotation is present, but no relationship
    of the kind points to the package
    """
    pkg, _, annot = _base_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    mock_doc.packages = [pkg]
    mock_doc.relationships = []
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, BASE_IMAGE) == []


def test_collect_image_items_skips_wrong_annotation_type(mock_doc: MagicMock) -> None:
    """
    BASE_IMAGE and ANCESTOR_IMAGE share (DESCENDANT_OF, TARGET);
    the annotation type is the only disambiguator. An ancestor-annotated
    package must not be collected as a base image.
    """
    pkg, rel, annot = _ancestor_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, BASE_IMAGE) == []


def test_get_annotation_by_spdx_id_filter_by_type_match(mock_doc: MagicMock) -> None:
    annot = KonfluxAnnotationManager.base_image("SPDXRef-x")
    mock_doc.annotations = [annot]

    assert (
        get_annotation_by_spdx_id_filter_by_type(
            mock_doc, "SPDXRef-x", AnnotationBaseImage
        )
        == annot
    )


def test_get_annotation_by_spdx_id_filter_by_type_no_match(mock_doc: MagicMock) -> None:
    annot = KonfluxAnnotationManager.base_image("SPDXRef-x")
    mock_doc.annotations = [annot]

    assert (
        get_annotation_by_spdx_id_filter_by_type(
            mock_doc, "SPDXRef-x", AnnotationAncestorImage
        )
        is None
    )


def test_get_annotation_by_spdx_id_filter_by_type_parse_fail(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING")
    bad = Annotation(
        "SPDXRef-x",
        AnnotationType.OTHER,
        KONFLUX_JSON_ACTOR,
        datetime.datetime.now(),
        "unexpected comment",  # non-JSON comment causing parse failure
    )
    mock_doc.annotations = [bad]

    assert (
        get_annotation_by_spdx_id_filter_by_type(
            mock_doc, "SPDXRef-x", AnnotationBaseImage
        )
        is None
    )
    assert any(
        "could not be parsed as a Konflux annotation" in message
        for message in caplog.messages
    )


def test_get_grandparent_and_ancestor_scratch_or_oci(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")
    mock_doc.annotations = []
    mock_doc.packages = []
    mock_doc.relationships = []
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    assert get_grandparent_and_ancestor_items_from_used_parent(mock_doc, "name") == []
    assert any(
        "Cannot determine parent of the" in message for message in caplog.messages
    )


def test_get_grandparent_and_ancestor_legacy(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    caplog.set_level("INFO")
    pkg, rel, annot = _legacy_grandparent_item("SPDXRef-grandparent", "SPDXRef-parent")
    mock_doc.packages = [pkg]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    result = get_grandparent_and_ancestor_items_from_used_parent(
        mock_doc, "SPDXRef-parent-name-from-component"
    )

    res_rel = result[0].relationship
    res_annot = result[0].annotation
    # legacy BUILD_TOOL_OF is converted to DESCENDANT_OF using the parent name
    # as referenced by the component
    assert res_rel == Relationship(
        "SPDXRef-parent-name-from-component",
        RelationshipType.DESCENDANT_OF,
        "SPDXRef-grandparent",
    )
    assert "is_ancestor_image" in res_annot.annotation_comment
    assert any("Legacy grandparent detected." in message for message in caplog.messages)


def test_get_grandparent_modified_and_ancestor_passed(mock_doc: MagicMock) -> None:
    gp_pkg, gp_rel, gp_annot = _base_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    anc_pkg, anc_rel, anc_annot = _ancestor_image_item(
        "SPDXRef-grandparent", "SPDXRef-ancestor"
    )
    mock_doc.packages = [gp_pkg, anc_pkg]
    mock_doc.relationships = [gp_rel, anc_rel]
    mock_doc.annotations = [gp_annot, anc_annot]
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    result = get_grandparent_and_ancestor_items_from_used_parent(
        mock_doc, "SPDXRef-parent-name-from-component"
    )

    assert len(result) == 2
    # grandparent is converted to an ancestor item
    gp_result_rel = result[0].relationship
    gp_result_annot = result[0].annotation
    assert gp_result_rel == Relationship(
        "SPDXRef-parent-name-from-component",
        RelationshipType.DESCENDANT_OF,
        "SPDXRef-grandparent",
    )
    assert "is_ancestor_image" in gp_result_annot.annotation_comment
    # deeper ancestors are passed through unchanged
    assert result[1] == ImageItem(anc_pkg, anc_rel, anc_annot)


def test_grandparent_has_multiple_base_images_failure(
    mock_doc: MagicMock,
) -> None:
    gp1 = _base_image_item("SPDXRef-parent", "SPDXRef-gp1")
    gp2 = _base_image_item("SPDXRef-parent-2", "SPDXRef-gp2")
    mock_doc.packages = [gp1[0], gp2[0]]
    mock_doc.relationships = [gp1[1], gp2[1]]
    mock_doc.annotations = [gp1[2], gp2[2]]
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    with pytest.raises(SBOMError):
        get_grandparent_and_ancestor_items_from_used_parent(mock_doc, "name")


def test_grandparent_has_multiple_legacy_base_images_failure(
    mock_doc: MagicMock,
) -> None:
    g1 = _legacy_grandparent_item("SPDXRef-gp1", "SPDXRef-parent")
    g2 = _legacy_grandparent_item("SPDXRef-gp2", "SPDXRef-parent")
    mock_doc.packages = [g1[0], g2[0]]
    mock_doc.relationships = [g1[1], g2[1]]
    mock_doc.annotations = [g1[2], g2[2]]
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    with pytest.raises(SBOMError):
        get_grandparent_and_ancestor_items_from_used_parent(mock_doc, "name")


@pytest.mark.parametrize(
    "item",
    [
        pytest.param(
            _base_image_item("SPDXRef-parent", "SPDXRef-grandparent"),
            id="mobster-era",
        ),
        pytest.param(
            _legacy_grandparent_item("SPDXRef-grandparent", "SPDXRef-parent"),
            id="legacy",
        ),
    ],
)
def test_process_grandparent_item_normalizes_input(
    item: tuple[Package, Relationship, Annotation],
) -> None:
    pkg, rel, annot = item

    result = process_grandparent_item(
        ImageItem(pkg, rel, annot), "SPDXRef-parent-name-from-component"
    )

    res_rel = result.relationship
    res_annot = result.annotation
    assert result.package.files_analyzed is False
    assert res_rel == Relationship(
        "SPDXRef-parent-name-from-component",
        RelationshipType.DESCENDANT_OF,
        "SPDXRef-grandparent",
    )
    assert "is_ancestor_image" in res_annot.annotation_comment
    assert "is_base_image" not in res_annot.annotation_comment


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


@pytest.mark.parametrize(
    ("relationships", "error_message"),
    [
        pytest.param(
            [
                Relationship(
                    "SPDXRef-spam-parent",
                    RelationshipType.BUILD_TOOL_OF,
                    "SPDXRef-spam",
                )
            ],
            "does not contain any DESCENDANT_OF relationship",
            id="no-descendant-of",
        ),
        pytest.param(
            [
                Relationship(
                    "SPDXRef-component",
                    RelationshipType.DESCENDANT_OF,
                    "SPDXRef-parent-one",
                ),
                Relationship(
                    "SPDXRef-component",
                    RelationshipType.DESCENDANT_OF,
                    "SPDXRef-parent-two",
                ),
            ],
            "contains multiple DESCENDANT_OF relationships",
            id="multiple-descendant-of",
        ),
    ],
)
def test_get_parent_spdx_id_from_component_invalid_relationships(
    mock_doc: MagicMock,
    relationships: list[Relationship],
    error_message: str,
) -> None:
    mock_doc.relationships = relationships
    with pytest.raises(SBOMError, match=error_message):
        get_parent_spdx_id_from_component(mock_doc)


def test_supply_image_packages() -> None:
    component_sbom_doc = MagicMock(spec=Document)
    component_sbom_doc.packages = []
    component_sbom_doc.annotations = []
    component_sbom_doc.relationships = []

    parent_sbom_doc = MagicMock(spec=Document)
    parent_sbom_doc.packages = []
    parent_sbom_doc.annotations = []

    stats = MatchingStatistics()

    ancestor_pkg, ancestor_rel, ancestor_annot = _ancestor_image_item(
        "SPDXRef-parent", "SPDXRef-grandparent"
    )
    image_packages = [ImageItem(ancestor_pkg, ancestor_rel, ancestor_annot)]

    resolver = ComponentRelationshipResolver(
        [], parent_sbom_doc, component_sbom_doc, stats
    )
    resolver.supply_image_packages(image_packages)

    assert ancestor_pkg in component_sbom_doc.packages
    assert ancestor_rel in component_sbom_doc.relationships
    assert ancestor_annot in component_sbom_doc.annotations
    assert "is_ancestor_image" in component_sbom_doc.annotations[0].annotation_comment


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
    ComponentRelationshipResolver._modify_relationship_in_component(
        component_relationship,
        parent_relationship,
        parent_spdx_id_from_component,
        parent_root_packages,
    )

    assert component_relationship == result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["identifier_type", "should_reparent"],
    [
        ("checksum", True),
        ("checksum", False),
        ("verification_code", True),
        ("verification_code", False),
        ("purl", True),
        ("purl", False),
    ],
)
@patch("mobster.cmd.generate.oci_image.contextual_sbom.parent.MatchingStatistics")
async def test_map_parent_to_component_and_update_component(
    mock_stats_class: MagicMock,
    identifier_type: str,
    should_reparent: bool,
) -> None:
    """
    Test package matching via ComponentRelationshipResolver using different
    identifier types.

    Verifies that:
    1. Resolver finds packages by checksum, verification_code, or purl
    2. Matching packages -> relationship modified to use parent SPDX ID
    3. Non-matching packages -> relationship unchanged
    4. Grandparent supplied to the component as an ancestor
    5. Statistics are properly recorded and logged
    """
    parent_spdx_id = "SPDXRef-parent-name-from-component"

    # Setup mock stats instance
    mock_stats = MagicMock()
    mock_stats_class.return_value = mock_stats

    # Setup parent SBOM with a grandparent (base image) and a test package
    # SPDXRef-parent DESCENDANT_OF SPDXRef-grandparent
    # SPDXRef-parent CONTAINS SPDXRef-package-1
    parent_sbom_doc = MagicMock(spec=Document)
    grandparent_pkg, grandparent_rel, grandparent_annot = _base_image_item(
        "SPDXRef-parent", "SPDXRef-grandparent"
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

    # Setup component SBOM with a matching/non-matching package
    # SPDXRef-component DESCENDANT_OF SPDXRef-parent
    # SPDXRef-component CONTAINS SPDXRef-package-1
    component_sbom_doc = MagicMock(spec=Document)
    component_test_pkg = create_package_with_identifier(
        "SPDXRef-package-1", identifier_type, matching_value=should_reparent
    )
    original_rel = Relationship(
        "SPDXRef-component", RelationshipType.CONTAINS, "SPDXRef-package-1"
    )
    component_sbom_doc.packages = [component_test_pkg]
    component_sbom_doc.relationships = [original_rel]
    component_sbom_doc.annotations = []

    # Execute contextualization
    result = await map_parent_to_component_and_update_component(
        parent_sbom_doc,
        component_sbom_doc,
        parent_spdx_id,
    )

    # Verify relationship modification
    contains_rels = [
        r
        for r in result.relationships
        if r.relationship_type == RelationshipType.CONTAINS
    ]
    if should_reparent:
        # SPDXRef-parent CONTAINS SPDXRef-package-1
        assert any(r.spdx_element_id == parent_spdx_id for r in contains_rels), (
            f"Matching {identifier_type}: relationship should bear {parent_spdx_id}"
        )
    else:
        # SPDXRef-component CONTAINS SPDXRef-package-1
        assert original_rel in result.relationships, (
            f"Non-matching {identifier_type}: original relationship should remain"
        )

    # Verify grandparent supplied to component as an ancestor
    assert grandparent_pkg in result.packages
    assert (
        Relationship(
            parent_spdx_id,
            RelationshipType.DESCENDANT_OF,
            "SPDXRef-grandparent",
        )
        in result.relationships
    )
    assert any("is_ancestor_image" in a.annotation_comment for a in result.annotations)

    # Verify statistics were recorded
    mock_stats.record_component_packages.assert_called_once()
    mock_stats.record_parent_packages.assert_called_once()

    component_packages_call = mock_stats.record_component_packages.call_args[0][0]
    parent_packages_call = mock_stats.record_parent_packages.call_args[0][0]

    assert len(component_packages_call) == 1
    assert len(parent_packages_call) == 1

    if should_reparent:
        mock_stats.record_component_package_match.assert_called_once()
        mock_stats.record_parent_package_match.assert_called_once()
    else:
        mock_stats.record_component_package_match.assert_not_called()
        mock_stats.record_parent_package_match.assert_not_called()


@pytest.mark.asyncio
async def test_map_parent_to_component_raises_when_parent_root_is_missing(
    mock_doc: MagicMock,
) -> None:
    mock_doc.packages = []
    # Parent root is missing.
    mock_doc.relationships = []
    mock_doc.annotations = []
    mock_doc.creation_info.name = "quay.io/example/parent@sha256:1"

    component_sbom_doc = MagicMock(spec=Document)
    component_sbom_doc.packages = []
    component_sbom_doc.relationships = []
    component_sbom_doc.annotations = []

    with pytest.raises(
        SBOMError,
        match=(
            r"Parent SBOM cannot be used for contextualization: "
            r"quay\.io/example/parent@sha256:1: no SPDX root relationship "
            r"was found\."
        ),
    ):
        await map_parent_to_component_and_update_component(
            mock_doc,
            component_sbom_doc,
            "SPDXRef-parent",
        )


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
@patch("mobster.oci.cosign.anonymous_fetcher.AnonymousFetcher.fetch_sbom")
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
    assert sbom_doc is not None
    assert sbom_doc == json.loads(spdx_parent_sbom_bytes)
    assert sbom_doc.get("spdxVersion", "").startswith("SPDX-2.")
    assert (
        f"[Parent image content] The specific arch was successfully "
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
@patch("mobster.oci.cosign.anonymous_fetcher.AnonymousFetcher.fetch_sbom")
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
    mock_sbom = MagicMock()
    mock_sbom.format.is_spdx2.return_value = True
    mock_sbom.doc = {"documentNamespace": "https://test/parent"}
    mock_fetch_sbom.return_value = mock_sbom

    await download_parent_image_sbom(Image("foo", "sha256:1"), "bar")
    mock_fetch_sbom.assert_awaited_once_with(index_image)
    assert (
        "[Parent image content] Only the index image of parent "
        "was found for ref foo@sha256:1 and arch bar" in caplog.messages
    )


@pytest.mark.asyncio
@patch("mobster.oci.cosign.anonymous_fetcher.AnonymousFetcher.fetch_sbom")
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
@patch("mobster.oci.cosign.anonymous_fetcher.AnonymousFetcher.fetch_sbom")
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
        "[Parent image content] Contextual mechanism won't be used, SBOM format "
        "is not supported for this workflow." in caplog.messages
    )
