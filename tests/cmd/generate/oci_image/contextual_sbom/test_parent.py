import datetime
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.file import File
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    ADDITIONAL_IMAGE,
    ANCESTOR_IMAGE,
    BASE_IMAGE,
    BUILDER_IMAGE,
    INTERMEDIATE_IMAGE,
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
    get_annotations_by_spdx_id_filter_by_type,
    get_grandparent_and_ancestor_items_from_used_parent,
    get_parent_spdx_id_from_component,
    map_parent_to_component_and_update_component,
    process_builder_items,
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


def _builder_image_item(
    builder_id: str, built_image_id: str, stage_index: int = 0
) -> tuple[Package, Relationship, Annotation]:
    """`builder BUILD_TOOL_OF built image`, annotated is_builder_image."""
    pkg = Package(builder_id, "name", SpdxNoAssertion())
    rel = Relationship(builder_id, RelationshipType.BUILD_TOOL_OF, built_image_id)
    annot = KonfluxAnnotationManager.builder_image(builder_id, stage_index)
    return pkg, rel, annot


def _additional_image_item(
    additional_image_id: str, built_image_id: str
) -> tuple[Package, Relationship, Annotation]:
    """`additional image BUILD_TOOL_OF built image`, annotated as additional."""
    pkg = Package(additional_image_id, "name", SpdxNoAssertion())
    rel = Relationship(
        additional_image_id,
        RelationshipType.BUILD_TOOL_OF,
        built_image_id,
    )
    annot = KonfluxAnnotationManager.additional_image(additional_image_id)
    return pkg, rel, annot


def _intermediate_image_item(
    intermediate_id: str, builder_id: str, stage_index: int = 0
) -> tuple[Package, Relationship, Annotation]:
    """`intermediate DESCENDANT_OF builder`, annotated is_intermediate_image."""
    pkg = Package(intermediate_id, "name", SpdxNoAssertion())
    rel = Relationship(intermediate_id, RelationshipType.DESCENDANT_OF, builder_id)
    annot = KonfluxAnnotationManager.intermediate_image(intermediate_id, stage_index)
    return pkg, rel, annot


def test_collect_package_items(mock_doc: MagicMock) -> None:
    pkg1, rel1 = _content_item("SPDXRef-root", "SPDXRef-pkg1")
    pkg2, rel2 = _content_item("SPDXRef-root", "SPDXRef-pkg2")
    root = Package("SPDXRef-root", "root", SpdxNoAssertion())
    mock_doc.packages = [root, pkg1, pkg2]
    mock_doc.relationships = [rel1, rel2]

    assert collect_package_items(mock_doc) == [(pkg1, rel1), (pkg2, rel2)]


def test_collect_package_items_skips_package_without_contains(
    mock_doc: MagicMock,
) -> None:
    pkg1, rel1 = _content_item("SPDXRef-root", "SPDXRef-pkg1")
    root = Package("SPDXRef-root", "root", SpdxNoAssertion())
    orphan = Package("SPDXRef-orphan", "name", SpdxNoAssertion())
    mock_doc.packages = [root, pkg1, orphan]
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
    mock_doc.packages = [
        Package("SPDXRef-root", "root", SpdxNoAssertion()),
        Package("SPDXRef-other-root", "other-root", SpdxNoAssertion()),
        pkg,
    ]
    mock_doc.relationships = [rel, duplicate_rel]
    mock_doc.creation_info.document_namespace = "https://example.test/sbom"

    with pytest.raises(SBOMError) as error:
        collect_package_items(mock_doc)

    assert str(error.value) == (
        "[Parent image content] Multiple CONTAINS relationships found for "
        "content packages: SPDXRef-pkg: SPDXRef-root CONTAINS SPDXRef-pkg, "
        "SPDXRef-other-root CONTAINS SPDXRef-pkg. Document: "
        "https://example.test/sbom."
    )


def test_collect_package_items_warns_on_identical_relationship_triplet(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    """An identical CONTAINS triplet is one logical ownership relationship."""
    pkg, rel = _content_item("SPDXRef-root", "SPDXRef-pkg")
    duplicate_rel = Relationship("SPDXRef-root", RelationshipType.CONTAINS, pkg.spdx_id)
    mock_doc.packages = [
        Package("SPDXRef-root", "root", SpdxNoAssertion()),
        pkg,
    ]
    mock_doc.relationships = [rel, duplicate_rel]
    caplog.set_level("WARNING")

    assert collect_package_items(mock_doc) == [(pkg, rel), (pkg, duplicate_rel)]
    assert any(
        "content kind 'content package'" in message
        and "SPDXRef-root CONTAINS SPDXRef-pkg (2 occurrences)" in message
        for message in caplog.messages
    )


def test_collect_package_items_warns_on_identical_triplet_and_rejects_distinct_owner(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    """A repeated edge must not hide a distinct, ambiguous package owner."""
    pkg, relationship = _content_item("SPDXRef-root-a", "SPDXRef-pkg")
    duplicate_relationship = Relationship(
        "SPDXRef-root-a", RelationshipType.CONTAINS, pkg.spdx_id
    )
    distinct_relationship = Relationship(
        "SPDXRef-root-b", RelationshipType.CONTAINS, pkg.spdx_id
    )
    mock_doc.packages = [
        Package("SPDXRef-root-a", "root-a", SpdxNoAssertion()),
        Package("SPDXRef-root-b", "root-b", SpdxNoAssertion()),
        pkg,
    ]
    mock_doc.relationships = [
        relationship,
        duplicate_relationship,
        distinct_relationship,
    ]
    caplog.set_level("WARNING")

    with pytest.raises(SBOMError, match="Multiple CONTAINS relationships"):
        collect_package_items(mock_doc)

    assert any(
        "SPDXRef-root-a CONTAINS SPDXRef-pkg (2 occurrences)" in message
        for message in caplog.messages
    )


def test_collect_package_items_reports_all_duplicate_relationships(
    mock_doc: MagicMock,
) -> None:
    """
    collect_package_items is used for collecting
    content packages from component and parent SBOM
    All packages with ambiguous CONTAINS ownership
    from single document are reported together.
    """
    package1, relationship1 = _content_item("SPDXRef-root-1", "SPDXRef-pkg-1")
    package2, relationship2 = _content_item("SPDXRef-root-1", "SPDXRef-pkg-2")
    # invalid state: package is owned by two origins
    duplicate_relationship1 = Relationship(
        "SPDXRef-root-2", RelationshipType.CONTAINS, package1.spdx_id
    )
    duplicate_relationship2 = Relationship(
        "SPDXRef-root-3", RelationshipType.CONTAINS, package2.spdx_id
    )
    mock_doc.packages = [
        package1,
        package2,
        Package("SPDXRef-root-1", "root-1", SpdxNoAssertion()),
        Package("SPDXRef-root-2", "root-2", SpdxNoAssertion()),
        Package("SPDXRef-root-3", "root-3", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [
        relationship1,
        relationship2,
        duplicate_relationship1,
        duplicate_relationship2,
    ]

    with pytest.raises(SBOMError) as error:
        collect_package_items(mock_doc)

    message = str(error.value)
    assert "SPDXRef-pkg-1:" in message
    assert "SPDXRef-root-2 CONTAINS SPDXRef-pkg-1" in message
    assert "SPDXRef-pkg-2:" in message
    assert "SPDXRef-root-3 CONTAINS SPDXRef-pkg-2" in message


def test_collect_package_items_ignores_file_relationships(
    mock_doc: MagicMock,
) -> None:
    """Package-to-file evidence must not affect package collection."""
    package, package_rel = _content_item("SPDXRef-root", "SPDXRef-pkg")
    file_rel = Relationship(
        package.spdx_id,
        RelationshipType.CONTAINS,
        "SPDXRef-file",
    )
    mock_doc.packages = [
        Package("SPDXRef-root", "root", SpdxNoAssertion()),
        package,
    ]
    mock_doc.files = [File("file", "SPDXRef-file", [])]
    mock_doc.relationships = [package_rel, file_rel]

    assert collect_package_items(mock_doc) == [(package, package_rel)]


@pytest.mark.parametrize(
    ("subject", "target", "files"),
    [
        pytest.param(
            "SPDXRef-file",
            "SPDXRef-pkg",
            [File("file", "SPDXRef-file", [])],
            id="File CONTAINS package (invalid/unknown ownership model)",
        ),
        pytest.param(
            "SPDXRef-pkg",
            "SPDXRef-missing",
            [],
            id="Package CONTAINS missing package (invalid/unknown ownership model)",
        ),
    ],
)
def test_collect_package_items_warns_on_unsupported_contains_relationship(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
    subject: str,
    target: str,
    files: list[File],
) -> None:
    """CONTAINS relationships outside the ownership model warn and are skipped."""
    package, package_rel = _content_item("SPDXRef-root", "SPDXRef-pkg")
    unsupported_rel = Relationship(
        subject,
        RelationshipType.CONTAINS,
        target,
    )
    mock_doc.packages = [
        Package("SPDXRef-root", "root", SpdxNoAssertion()),
        package,
    ]
    mock_doc.files = files
    mock_doc.relationships = [package_rel, unsupported_rel]
    caplog.set_level("WARNING")

    assert collect_package_items(mock_doc) == [(package, package_rel)]
    assert any(
        "Skipping invalid CONTAINS relationship: "
        f"{subject} CONTAINS {target}." in message
        for message in caplog.messages
    )


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
        pytest.param(
            BUILDER_IMAGE,
            _builder_image_item("SPDXRef-builder", "SPDXRef-parent"),
            id="parent-builder-image",
        ),
        pytest.param(
            ADDITIONAL_IMAGE,
            _additional_image_item("SPDXRef-additional", "SPDXRef-parent"),
            id="parent-additional-image",
        ),
        pytest.param(
            INTERMEDIATE_IMAGE,
            _intermediate_image_item("SPDXRef-intermediate", "SPDXRef-builder"),
            id="builder-intermediate-image",
        ),
        pytest.param(
            LEGACY_BASE_IMAGE,
            _legacy_grandparent_item("SPDXRef-grandparent", "SPDXRef-parent"),
            id="legacy-grandparent-image",
        ),
    ],
)
def test_collect_image_items_by_content_kind(
    mock_doc: MagicMock,
    kind: ContentKind,
    item: tuple[Package, Relationship, Annotation],
) -> None:
    pkg, rel, annot = item
    endpoint_ids = {
        endpoint_id
        for endpoint_id in (rel.spdx_element_id, rel.related_spdx_element_id)
        if isinstance(endpoint_id, str) and endpoint_id != pkg.spdx_id
    }
    mock_doc.packages = [
        pkg,
        *[
            Package(endpoint_id, "related-image", SpdxNoAssertion())
            for endpoint_id in endpoint_ids
        ],
    ]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, kind) == [ImageItem(pkg, rel, [annot])]


def test_collect_image_items_preserves_multiple_annotations(
    mock_doc: MagicMock,
) -> None:
    """
    Preserve annotations for an image used in two build stages and as a base.

    The same image package has two builder annotations and one base-image
    annotation. Each collector preserves only annotations matching its kind.
    """
    builder_pkg = Package("SPDXRef-builder", "builder", SpdxNoAssertion())
    parent_pkg = Package("SPDXRef-parent", "parent", SpdxNoAssertion())
    component_pkg = Package("SPDXRef-component", "component", SpdxNoAssertion())

    builder_parent_rel = Relationship(
        builder_pkg.spdx_id,
        RelationshipType.BUILD_TOOL_OF,
        parent_pkg.spdx_id,
    )
    component_parent_rel = Relationship(
        "SPDXRef-component",
        RelationshipType.DESCENDANT_OF,
        builder_pkg.spdx_id,
    )
    annotations = [
        KonfluxAnnotationManager.builder_image(builder_pkg.spdx_id, 0),
        KonfluxAnnotationManager.builder_image(builder_pkg.spdx_id, 1),
    ]
    base_annotation = KonfluxAnnotationManager.base_image(builder_pkg.spdx_id)

    mock_doc.packages = [builder_pkg, parent_pkg, component_pkg]
    mock_doc.relationships = [builder_parent_rel, component_parent_rel]
    mock_doc.annotations = [*annotations, base_annotation]

    # every collector preserves annotations of its kinds
    assert collect_image_items(mock_doc, BUILDER_IMAGE) == [
        ImageItem(builder_pkg, builder_parent_rel, annotations),
    ]
    assert collect_image_items(mock_doc, BASE_IMAGE) == [
        ImageItem(builder_pkg, component_parent_rel, [base_annotation]),
    ]


def test_collect_image_items_legacy_grandparent(mock_doc: MagicMock) -> None:
    pkg, rel, annot = _legacy_grandparent_item("SPDXRef-grandparent", "SPDXRef-parent")
    mock_doc.packages = [
        pkg,
        Package("SPDXRef-parent", "parent", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, LEGACY_BASE_IMAGE) == [
        ImageItem(pkg, rel, [annot])
    ]


def test_collect_image_items_collects_reused_builder_across_ancestors(
    mock_doc: MagicMock,
) -> None:
    """
    Collect one builder reused by the parent and
    grandparent images from parent contextual SBOM.
    """
    parent_doc = mock_doc
    builder_id = "SPDXRef-builder"
    parent_id = "SPDXRef-parent"
    grandparent_id = "SPDXRef-grandparent"

    builder_pkg = Package(builder_id, "builder", SpdxNoAssertion())
    parent_pkg = Package(parent_id, "parent", SpdxNoAssertion())
    grandparent_pkg = Package(grandparent_id, "grandparent", SpdxNoAssertion())

    parent_ancestor_rel = Relationship(
        parent_id,
        RelationshipType.DESCENDANT_OF,
        grandparent_id,
    )
    # identical builder builds parent and grandparent
    builder_parent_rel = Relationship(
        builder_id,
        RelationshipType.BUILD_TOOL_OF,
        parent_id,
    )
    builder_grandparent_rel = Relationship(
        builder_id,
        RelationshipType.BUILD_TOOL_OF,
        grandparent_id,
    )
    builder_annotation = KonfluxAnnotationManager.builder_image(builder_id, 0)

    parent_doc.packages = [builder_pkg, parent_pkg, grandparent_pkg]
    parent_doc.relationships = [
        parent_ancestor_rel,
        builder_parent_rel,
        builder_grandparent_rel,
    ]
    parent_doc.annotations = [builder_annotation]

    # The collector returns both relationships.
    assert collect_image_items(parent_doc, BUILDER_IMAGE) == [
        ImageItem(builder_pkg, builder_parent_rel, [builder_annotation]),
        ImageItem(builder_pkg, builder_grandparent_rel, [builder_annotation]),
    ]


def test_collect_image_items_warns_on_identical_builder_relationship_triplet(
    mock_doc: MagicMock,
    caplog: LogCaptureFixture,
) -> None:
    """A repeated builder relationship is warning-only for this content kind."""
    builder_pkg, builder_rel, builder_annotation = _builder_image_item(
        "SPDXRef-builder", "SPDXRef-parent"
    )
    duplicate_rel = Relationship(
        builder_pkg.spdx_id,
        RelationshipType.BUILD_TOOL_OF,
        "SPDXRef-parent",
    )
    parent_pkg = Package("SPDXRef-parent", "parent", SpdxNoAssertion())
    mock_doc.packages = [builder_pkg, parent_pkg]
    mock_doc.relationships = [builder_rel, duplicate_rel]
    mock_doc.annotations = [builder_annotation]
    caplog.set_level("WARNING")

    assert collect_image_items(mock_doc, BUILDER_IMAGE) == [
        ImageItem(builder_pkg, builder_rel, [builder_annotation]),
        ImageItem(builder_pkg, duplicate_rel, [builder_annotation]),
    ]
    assert any(
        "content kind 'builder image'" in message
        and "SPDXRef-builder BUILD_TOOL_OF SPDXRef-parent (2 occurrences)" in message
        for message in caplog.messages
    )


@pytest.mark.parametrize(
    ("kind", "item", "additional_rel", "supporting_packages"),
    [
        pytest.param(
            BASE_IMAGE,
            _base_image_item("SPDXRef-parent", "SPDXRef-grandparent"),
            Relationship(
                "SPDXRef-other-parent",
                RelationshipType.DESCENDANT_OF,
                "SPDXRef-grandparent",
            ),
            [
                Package("SPDXRef-parent", "parent", SpdxNoAssertion()),
                Package("SPDXRef-other-parent", "other-parent", SpdxNoAssertion()),
            ],
            id="A base image (of the parent) cannot have multiple descendants",
        ),
        pytest.param(
            ANCESTOR_IMAGE,
            _ancestor_image_item("SPDXRef-grandparent", "SPDXRef-ancestor"),
            Relationship(
                "SPDXRef-other-grandparent",
                RelationshipType.DESCENDANT_OF,
                "SPDXRef-ancestor",
            ),
            [
                Package("SPDXRef-grandparent", "grandparent", SpdxNoAssertion()),
                Package(
                    "SPDXRef-other-grandparent",
                    "other-grandparent",
                    SpdxNoAssertion(),
                ),
            ],
            id="An ancestor image cannot have multiple descendants",
        ),
        pytest.param(
            LEGACY_BASE_IMAGE,
            _legacy_grandparent_item("SPDXRef-grandparent", "SPDXRef-parent"),
            Relationship(
                "SPDXRef-grandparent",
                RelationshipType.BUILD_TOOL_OF,
                "SPDXRef-other-parent",
            ),
            [
                Package("SPDXRef-parent", "parent", SpdxNoAssertion()),
                Package("SPDXRef-other-parent", "other-parent", SpdxNoAssertion()),
            ],
            id="A legacy base image (of the parent) cannot have multiple descendants",
        ),
        pytest.param(
            INTERMEDIATE_IMAGE,
            _intermediate_image_item("SPDXRef-builder-intermediate", "SPDXRef-builder"),
            Relationship(
                "SPDXRef-builder-intermediate",
                RelationshipType.DESCENDANT_OF,
                "SPDXRef-other-builder",
            ),
            [
                Package("SPDXRef-builder", "builder", SpdxNoAssertion()),
                Package("SPDXRef-other-builder", "other-builder", SpdxNoAssertion()),
            ],
            id=(
                "Intermediates from different ancestors must not reuse one "
                "SPDX ID because they represent different source images; "
                "TO DO: contextualization must prevent this collision"
            ),
        ),
    ],
)
def test_collect_image_items_rejects_multiple_relationships_for_restricted_kinds(
    mock_doc: MagicMock,
    kind: ContentKind,
    item: tuple[Package, Relationship, Annotation],
    additional_rel: Relationship,
    supporting_packages: list[Package],
) -> None:
    """Restricted image content kinds allow only one matching relationship."""
    parent_doc = mock_doc
    pkg, rel, annot = item
    parent_doc.packages = [pkg, *supporting_packages]
    parent_doc.relationships = [rel, additional_rel]
    parent_doc.annotations = [annot]

    with pytest.raises(SBOMError):
        collect_image_items(parent_doc, kind)


def test_collect_image_items_skips_missing_annotation(mock_doc: MagicMock) -> None:
    """
    Image package + relationship are present,
    but no annotation to disambiguate the kind
    """
    pkg, rel, _ = _base_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    mock_doc.packages = [
        pkg,
        Package(rel.spdx_element_id, "parent", SpdxNoAssertion()),
    ]
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


@pytest.mark.parametrize(
    ("kind", "item"),
    [
        pytest.param(
            BASE_IMAGE,
            _base_image_item("SPDXRef-parent", "SPDXRef-grandparent"),
            id="base-image",
        ),
        pytest.param(
            ANCESTOR_IMAGE,
            _ancestor_image_item("SPDXRef-grandparent", "SPDXRef-ancestor"),
            id="ancestor-image",
        ),
    ],
)
def test_collect_image_items_rejects_dangling_relationship(
    mock_doc: MagicMock,
    kind: ContentKind,
    item: tuple[Package, Relationship, Annotation],
) -> None:
    """Image relationships require both image package endpoints."""
    pkg, rel, annot = item
    # Keep the relationship subject present and omit its target package.
    mock_doc.packages = [
        Package(rel.spdx_element_id, "child", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    with pytest.raises(SBOMError, match="Invalid image relationship 'DESCENDANT_OF'"):
        collect_image_items(mock_doc, kind)


def test_collect_image_items_skips_wrong_annotation_type(mock_doc: MagicMock) -> None:
    """
    BASE_IMAGE and ANCESTOR_IMAGE share (DESCENDANT_OF, TARGET);
    the annotation type is the only disambiguator. An ancestor-annotated
    package must not be collected as a base image.
    """
    pkg, rel, annot = _ancestor_image_item("SPDXRef-parent", "SPDXRef-grandparent")
    mock_doc.packages = [
        pkg,
        Package(rel.spdx_element_id, "parent", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]

    assert collect_image_items(mock_doc, BASE_IMAGE) == []


def test_get_annotations_by_spdx_id_filter_by_type_match(mock_doc: MagicMock) -> None:
    annot = KonfluxAnnotationManager.base_image("SPDXRef-x")
    mock_doc.annotations = [annot]

    assert get_annotations_by_spdx_id_filter_by_type(
        mock_doc, "SPDXRef-x", AnnotationBaseImage
    ) == [annot]


def test_get_annotations_by_spdx_id_filter_by_type_no_match(
    mock_doc: MagicMock,
) -> None:
    annot = KonfluxAnnotationManager.base_image("SPDXRef-x")
    mock_doc.annotations = [annot]

    assert (
        get_annotations_by_spdx_id_filter_by_type(
            mock_doc, "SPDXRef-x", AnnotationAncestorImage
        )
        == []
    )


def test_get_annotations_by_spdx_id_filter_by_type_parse_fail(
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
    mock_doc.creation_info.name = "quay.io/example/parent@sha256:1"

    assert (
        get_annotations_by_spdx_id_filter_by_type(
            mock_doc, "SPDXRef-x", AnnotationBaseImage
        )
        == []
    )
    assert (
        "[Parent image content] Annotation 'SPDXRef-x' from parent SBOM "
        "'quay.io/example/parent@sha256:1' has a comment that could not be "
        "parsed as a Konflux annotation: 'unexpected comment'." in caplog.messages
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
    mock_doc.packages = [
        pkg,
        Package("SPDXRef-parent", "parent", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [rel]
    mock_doc.annotations = [annot]
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    result = get_grandparent_and_ancestor_items_from_used_parent(
        mock_doc, "SPDXRef-parent-name-from-component"
    )

    res_rel = result[0].relationship
    res_annot = result[0].annotations[0]
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
    mock_doc.packages = [
        gp_pkg,
        anc_pkg,
        Package(gp_rel.spdx_element_id, "parent", SpdxNoAssertion()),
    ]
    mock_doc.relationships = [gp_rel, anc_rel]
    mock_doc.annotations = [gp_annot, anc_annot]
    mock_doc.creation_info.name = "quay.io/foo@sha256:1"

    result = get_grandparent_and_ancestor_items_from_used_parent(
        mock_doc, "SPDXRef-parent-name-from-component"
    )

    assert len(result) == 2
    # grandparent is converted to an ancestor item
    gp_result_rel = result[0].relationship
    gp_result_annot = result[0].annotations[0]
    assert gp_result_rel == Relationship(
        "SPDXRef-parent-name-from-component",
        RelationshipType.DESCENDANT_OF,
        "SPDXRef-grandparent",
    )
    assert "is_ancestor_image" in gp_result_annot.annotation_comment
    # deeper ancestors are passed through unchanged
    assert result[1] == ImageItem(anc_pkg, anc_rel, [anc_annot])


def test_grandparent_has_multiple_base_images_failure(
    mock_doc: MagicMock,
) -> None:
    gp1 = _base_image_item("SPDXRef-parent", "SPDXRef-gp1")
    gp2 = _base_image_item("SPDXRef-parent-2", "SPDXRef-gp2")
    mock_doc.packages = [
        gp1[0],
        gp2[0],
        Package(gp1[1].spdx_element_id, "parent", SpdxNoAssertion()),
        Package(gp2[1].spdx_element_id, "other-parent", SpdxNoAssertion()),
    ]
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
    mock_doc.packages = [
        g1[0],
        g2[0],
        Package("SPDXRef-parent", "parent", SpdxNoAssertion()),
    ]
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
    pkg.files_analyzed = True
    original_annotation_comment = annot.annotation_comment

    result = process_grandparent_item(
        ImageItem(pkg, rel, [annot]), "SPDXRef-parent-name-from-component"
    )

    res_rel = result.relationship
    res_annot = result.annotations[0]
    assert result.package.files_analyzed is False
    assert res_rel == Relationship(
        "SPDXRef-parent-name-from-component",
        RelationshipType.DESCENDANT_OF,
        "SPDXRef-grandparent",
    )
    assert "is_ancestor_image" in res_annot.annotation_comment
    assert "is_base_image" not in res_annot.annotation_comment
    assert result.package is not pkg
    assert res_annot is not annot
    assert pkg.files_analyzed is True
    assert annot.annotation_comment == original_annotation_comment


def test_process_builder_items_rename_parent_target() -> None:
    pkg1, rel1, annot1 = _additional_image_item("SPDXRef-additional", "SPDXRef-parent")
    pkg2, rel2, annot2 = _builder_image_item("SPDXRef-builder", "SPDXRef-grandparent")
    pkg3, rel3, annot3 = _builder_image_item("SPDXRef-parent-builder", "SPDXRef-parent")

    result = process_builder_items(
        builder_items=[
            ImageItem(pkg1, rel1, [annot1]),
            ImageItem(pkg2, rel2, [annot2]),
            ImageItem(pkg3, rel3, [annot3]),
        ],
        parent_spdx_id_from_component="SPDXRef-parent-name-from-component",
        parent_root_packages=["SPDXRef-parent"],
    )

    assert result == [
        ImageItem(
            pkg1,
            Relationship(
                "SPDXRef-additional",
                RelationshipType.BUILD_TOOL_OF,
                "SPDXRef-parent-name-from-component",
            ),
            [annot1],
        ),
        ImageItem(pkg2, rel2, [annot2]),
        ImageItem(
            pkg3,
            Relationship(
                "SPDXRef-parent-builder",
                RelationshipType.BUILD_TOOL_OF,
                "SPDXRef-parent-name-from-component",
            ),
            [annot3],
        ),
    ]


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


def test_supply_image_packages_merges_reused_builder_across_images() -> None:
    """Supply one identical builder reused across component, parent, and ancestor."""
    builder_id = "SPDXRef-shared-builder"
    builder_pkg = Package(builder_id, "builder", SpdxNoAssertion())
    component_rel = Relationship(
        builder_id,
        RelationshipType.BUILD_TOOL_OF,
        "SPDXRef-component",
    )
    parent_rel = Relationship(
        builder_id,
        RelationshipType.BUILD_TOOL_OF,
        "SPDXRef-parent",
    )
    grandparent_rel = Relationship(
        builder_id,
        RelationshipType.BUILD_TOOL_OF,
        "SPDXRef-grandparent",
    )
    component_annot = KonfluxAnnotationManager.builder_image(builder_id, 0)
    parent_annot = KonfluxAnnotationManager.builder_image(builder_id, 0)
    grandparent_annot = KonfluxAnnotationManager.builder_image(builder_id, 0)

    parent_builder_pkg = Package(builder_id, "builder", SpdxNoAssertion())
    parent_pkg = Package("SPDXRef-parent", "parent", SpdxNoAssertion())
    grandparent_pkg = Package("SPDXRef-grandparent", "grandparent", SpdxNoAssertion())

    component_sbom_doc = MagicMock(spec=Document)
    component_sbom_doc.packages = [builder_pkg]
    component_sbom_doc.relationships = [component_rel]
    component_sbom_doc.annotations = [component_annot]

    parent_sbom_doc = MagicMock(spec=Document)
    parent_sbom_doc.packages = [parent_builder_pkg, parent_pkg, grandparent_pkg]
    parent_sbom_doc.relationships = [parent_rel, grandparent_rel]
    parent_sbom_doc.annotations = [parent_annot, grandparent_annot]

    parent_image_items = collect_image_items(parent_sbom_doc, BUILDER_IMAGE)

    resolver = ComponentRelationshipResolver(
        [], parent_sbom_doc, component_sbom_doc, MatchingStatistics()
    )
    resolver.supply_image_packages(parent_image_items)

    # package is deduplicated
    assert component_sbom_doc.packages == [builder_pkg]
    # All relationships and annotations must be preserved.
    assert component_sbom_doc.relationships == [
        component_rel,
        parent_rel,
        grandparent_rel,
    ]
    assert component_sbom_doc.annotations == [
        component_annot,
        parent_annot,
        grandparent_annot,
    ]


def test_supply_image_packages_preserves_builder_and_additional_roles() -> None:
    """Supply a shared image package with builder and additional roles."""
    shared_image_id = "SPDXRef-shared-image"
    shared_image_pkg = Package(shared_image_id, "shared-image", SpdxNoAssertion())
    parent_pkg = Package("SPDXRef-parent", "parent", SpdxNoAssertion())
    grandparent_pkg = Package("SPDXRef-grandparent", "grandparent", SpdxNoAssertion())
    builder_rel = Relationship(
        shared_image_id,
        RelationshipType.BUILD_TOOL_OF,
        grandparent_pkg.spdx_id,
    )
    additional_rel = Relationship(
        shared_image_id,
        RelationshipType.BUILD_TOOL_OF,
        parent_pkg.spdx_id,
    )
    builder_annot = KonfluxAnnotationManager.builder_image(shared_image_id, 0)
    additional_annot = KonfluxAnnotationManager.additional_image(shared_image_id)

    parent_sbom_doc = MagicMock(spec=Document)
    parent_sbom_doc.packages = [shared_image_pkg, parent_pkg, grandparent_pkg]
    parent_sbom_doc.relationships = [builder_rel, additional_rel]
    parent_sbom_doc.annotations = [builder_annot, additional_annot]

    component_sbom_doc = MagicMock(spec=Document)
    component_sbom_doc.packages = []
    component_sbom_doc.relationships = []
    component_sbom_doc.annotations = []

    resolver = ComponentRelationshipResolver(
        [], parent_sbom_doc, component_sbom_doc, MatchingStatistics()
    )
    resolver.supply_image_packages(
        collect_image_items(parent_sbom_doc, BUILDER_IMAGE)
        + collect_image_items(parent_sbom_doc, ADDITIONAL_IMAGE)
    )

    assert component_sbom_doc.packages == [shared_image_pkg]
    assert component_sbom_doc.relationships == [builder_rel, additional_rel]
    assert component_sbom_doc.annotations == [builder_annot, additional_annot]


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
    component_root_pkg = Package("SPDXRef-component", "component", SpdxNoAssertion())
    component_test_pkg = create_package_with_identifier(
        "SPDXRef-package-1", identifier_type, matching_value=should_reparent
    )
    original_rel = Relationship(
        "SPDXRef-component", RelationshipType.CONTAINS, "SPDXRef-package-1"
    )
    component_sbom_doc.packages = [component_root_pkg, component_test_pkg]
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
    supplied_grandparent = next(
        package
        for package in result.packages
        if package.spdx_id == grandparent_pkg.spdx_id
    )
    assert supplied_grandparent is not grandparent_pkg
    assert supplied_grandparent.files_analyzed is False
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
@pytest.mark.parametrize(
    (
        "builder_id",
        "builder_target_id",
        "intermediate_id",
        "builder_content_id",
        "intermediate_content_id",
        "expected_builder_target_parent",
    ),
    [
        pytest.param(
            "SPDXRef-parent-builder",
            "SPDXRef-parent",
            "SPDXRef-parent-intermediate",
            "SPDXRef-parent-builder-content",
            "SPDXRef-parent-intermediate-content",
            "SPDXRef-parent-name-from-component",
            id="Parent builder subtree",
        ),
        pytest.param(
            "SPDXRef-grandparent-builder",
            "SPDXRef-grandparent",
            "SPDXRef-grandparent-intermediate",
            "SPDXRef-grandparent-builder-content",
            "SPDXRef-grandparent-intermediate-content",
            "SPDXRef-grandparent",
            id="Ancestor builder subtree",
        ),
    ],
)
@patch("mobster.cmd.generate.oci_image.contextual_sbom.parent.MatchingStatistics")
async def test_map_parent_to_component_supplies_builder_and_intermediate_subtree(
    mock_stats_class: MagicMock,
    builder_id: str,
    builder_target_id: str,
    intermediate_id: str,
    builder_content_id: str,
    intermediate_content_id: str,
    expected_builder_target_parent: str,
) -> None:
    """
    Supply parent and ancestor builder subtrees and preserve their
    contextualized package ownership.

    A builder of the used parent is aligned with the component's parent SPDX ID.
    A builder of an ancestor remains attached to that ancestor. Content packages
    retain their builder or intermediate image owners.
    """
    parent_spdx_id = "SPDXRef-parent-name-from-component"

    parent_sbom_doc = MagicMock(spec=Document)
    # parent image has one builder with intermediate image
    grandparent_pkg, grandparent_rel, grandparent_annot = _base_image_item(
        "SPDXRef-parent", "SPDXRef-grandparent"
    )
    builder_pkg, builder_rel, builder_annot = _builder_image_item(
        builder_id, builder_target_id
    )
    intermediate_pkg, intermediate_rel, intermediate_annot = _intermediate_image_item(
        intermediate_id, builder_id
    )
    # builder and intermediate content package
    builder_content_pkg = create_package_with_identifier(builder_content_id, "checksum")
    builder_content_rel = Relationship(
        builder_id,
        RelationshipType.CONTAINS,
        builder_content_id,
    )
    intermediate_content_pkg = create_package_with_identifier(
        intermediate_content_id, "verification_code"
    )
    intermediate_content_rel = Relationship(
        intermediate_id,
        RelationshipType.CONTAINS,
        intermediate_content_id,
    )
    root_pkg, root_rel = get_root_package_items("SPDXRef-parent")
    parent_sbom_doc.packages = [
        grandparent_pkg,
        root_pkg,
        builder_pkg,
        intermediate_pkg,
        builder_content_pkg,
        intermediate_content_pkg,
    ]
    parent_sbom_doc.relationships = [
        grandparent_rel,
        root_rel,
        builder_rel,
        intermediate_rel,
        builder_content_rel,
        intermediate_content_rel,
    ]
    parent_sbom_doc.annotations = [
        grandparent_annot,
        builder_annot,
        intermediate_annot,
    ]

    component_sbom_doc = MagicMock(spec=Document)
    # builder and intermediate content package in component before contextualization
    component_root_pkg = Package("SPDXRef-component", "component", SpdxNoAssertion())
    component_builder_content_pkg = create_package_with_identifier(
        "SPDXRef-component-builder-content", "checksum"
    )
    component_intermediate_content_pkg = create_package_with_identifier(
        "SPDXRef-component-intermediate-content", "verification_code"
    )
    component_sbom_doc.packages = [
        component_root_pkg,
        component_builder_content_pkg,
        component_intermediate_content_pkg,
    ]
    component_sbom_doc.relationships = [
        Relationship(
            "SPDXRef-component",
            RelationshipType.CONTAINS,
            "SPDXRef-component-builder-content",
        ),
        Relationship(
            "SPDXRef-component",
            RelationshipType.CONTAINS,
            "SPDXRef-component-intermediate-content",
        ),
    ]
    component_sbom_doc.annotations = []

    mock_stats_class.return_value = MagicMock()

    component_result = await map_parent_to_component_and_update_component(
        parent_sbom_doc,
        component_sbom_doc,
        parent_spdx_id,
    )

    # Verify that builder and intermediate image packages are inherited from the parent.
    assert builder_pkg in component_result.packages
    assert intermediate_pkg in component_result.packages
    # After matching, verify that builder and intermediate content packages are
    # reparented correctly.
    assert (
        Relationship(
            builder_id,
            RelationshipType.CONTAINS,
            "SPDXRef-component-builder-content",
        )
        in component_result.relationships
    )
    assert (
        Relationship(
            intermediate_id,
            RelationshipType.CONTAINS,
            "SPDXRef-component-intermediate-content",
        )
        in component_result.relationships
    )
    # component does not indicate that contains builder \
    # intermediate originated packages anymore
    assert (
        Relationship(
            "SPDXRef-component",
            RelationshipType.CONTAINS,
            "SPDXRef-component-builder-content",
        )
        not in component_result.relationships
    )
    assert (
        Relationship(
            "SPDXRef-component",
            RelationshipType.CONTAINS,
            "SPDXRef-component-intermediate-content",
        )
        not in component_result.relationships
    )
    # Verify that the inherited builder is bound to the correct parent or
    # ancestor image.
    assert (
        Relationship(
            builder_id,
            RelationshipType.BUILD_TOOL_OF,
            expected_builder_target_parent,
        )
        in component_result.relationships
    )
    # All other relationships and annotations must be inherited
    assert intermediate_rel in component_result.relationships
    assert builder_annot in component_result.annotations
    assert intermediate_annot in component_result.annotations


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.contextual_sbom.parent.MatchingStatistics")
async def test_map_parent_to_component_supplies_additional_image_content(
    mock_stats_class: MagicMock,
) -> None:
    """Inherit an additional image, its content, and its relationship."""
    parent_spdx_id = "SPDXRef-parent-name-from-component"
    parent_root_pkg, parent_root_rel = get_root_package_items("SPDXRef-parent")
    additional_pkg, additional_rel, additional_annot = _additional_image_item(
        "SPDXRef-additional-image", "SPDXRef-parent"
    )
    parent_content_pkg = create_package_with_identifier(
        "SPDXRef-parent-additional-content", "checksum"
    )
    parent_content_rel = Relationship(
        additional_pkg.spdx_id,
        RelationshipType.CONTAINS,
        parent_content_pkg.spdx_id,
    )
    parent_sbom_doc = MagicMock(spec=Document)
    parent_sbom_doc.packages = [
        parent_root_pkg,
        additional_pkg,
        parent_content_pkg,
    ]
    parent_sbom_doc.relationships = [
        parent_root_rel,
        additional_rel,
        parent_content_rel,
    ]
    parent_sbom_doc.annotations = [additional_annot]

    component_content_pkg = create_package_with_identifier(
        "SPDXRef-component-additional-content", "checksum"
    )
    component_sbom_doc = MagicMock(spec=Document)
    component_sbom_doc.packages = [
        Package("SPDXRef-component", "component", SpdxNoAssertion()),
        component_content_pkg,
    ]
    component_sbom_doc.relationships = [
        Relationship(
            "SPDXRef-component",
            RelationshipType.CONTAINS,
            component_content_pkg.spdx_id,
        )
    ]
    component_sbom_doc.annotations = []
    mock_stats_class.return_value = MagicMock()

    result = await map_parent_to_component_and_update_component(
        parent_sbom_doc,
        component_sbom_doc,
        parent_spdx_id,
    )

    assert additional_pkg in result.packages
    assert additional_annot in result.annotations
    assert (
        Relationship(
            additional_pkg.spdx_id,
            RelationshipType.BUILD_TOOL_OF,
            parent_spdx_id,
        )
        in result.relationships
    )
    assert (
        Relationship(
            additional_pkg.spdx_id,
            RelationshipType.CONTAINS,
            component_content_pkg.spdx_id,
        )
        in result.relationships
    )
    assert (
        Relationship(
            "SPDXRef-component",
            RelationshipType.CONTAINS,
            component_content_pkg.spdx_id,
        )
        not in result.relationships
    )


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
async def test_map_parent_to_component_allows_parent_built_from_scratch(
    mock_doc: MagicMock,
) -> None:
    """Allow a scratch-based parent with a builder but no grandparent."""
    root_pkg, root_rel = get_root_package_items("SPDXRef-parent")
    builder_pkg, builder_rel, builder_annot = _builder_image_item(
        "SPDXRef-builder", "SPDXRef-parent"
    )
    mock_doc.packages = [root_pkg, builder_pkg]
    mock_doc.relationships = [root_rel, builder_rel]
    mock_doc.annotations = [builder_annot]
    mock_doc.creation_info.name = "quay.io/example/scratch-parent@sha256:1"
    mock_doc.creation_info.document_namespace = "https://test/scratch-parent"

    component_sbom_doc = MagicMock(spec=Document)
    component_sbom_doc.packages = []
    component_sbom_doc.relationships = []
    component_sbom_doc.annotations = []
    component_sbom_doc.creation_info.document_namespace = "https://test/component"

    parent_name_from_component = "SPDXRef-parent-from-component"
    result = await map_parent_to_component_and_update_component(
        mock_doc,
        component_sbom_doc,
        parent_name_from_component,
    )

    assert result is component_sbom_doc
    assert builder_pkg in result.packages
    assert (
        Relationship(
            "SPDXRef-builder",
            RelationshipType.BUILD_TOOL_OF,
            parent_name_from_component,
        )
        in result.relationships
    )
    assert builder_annot in result.annotations


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
        "[Parent image content] Contextual mechanism won't be used, there is no "
        "parent image." in caplog.messages
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
    caplog.set_level("INFO")
    mock_fetch_sbom.side_effect = SBOMError("No SBOM :(")
    assert (
        await download_parent_image_sbom(
            Image("foo", "sha256:1"), "totally existing arch"
        )
        is None
    )
    assert (
        "[Parent image content] Contextual mechanism won't be used, there is no "
        "parent image SBOM." in caplog.messages
    )


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
