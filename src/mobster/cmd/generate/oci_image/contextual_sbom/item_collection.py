"""Collection and validation of contextual items for parent-based contextualization."""

import logging
from collections import Counter
from dataclasses import dataclass

from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    CONTENT_PACKAGE,
    ContentKind,
)
from mobster.cmd.generate.oci_image.spdx_utils import (
    AnnotationImage,
    AnnotationParseError,
    KonfluxAnnotationManager,
    get_annotations_by_spdx_id,
)
from mobster.error import SBOMError

LOGGER = logging.getLogger(__name__)


@dataclass
class ImageItem:
    """
    A resolved image package with its relationship and annotations, ready to
    be supplied to the component SBOM.
    """

    package: Package
    relationship: Relationship
    annotations: list[Annotation]


@dataclass(frozen=True)
class ContentItem:
    """A content package and the relationship that identifies its owner."""

    package: Package
    relationship: Relationship


def get_annotations_by_spdx_id_filter_by_type(
    parent_sbom_doc: Document,
    spdx_id: str,
    annotation_type: type[AnnotationImage],
) -> list[Annotation]:
    """
    Return all annotations with the given Konflux annotation type for a package
    SPDX ID.

    An image package may have multiple annotations of the requested type, for
    example annotations for multiple builder or intermediate stages. The same
    package may also have annotations for other roles, such as a parent and a
    builder, but those roles are collected in separate `ContentKind` calls.
    Therefore, only annotations matching the requested type are returned;
    annotations for other roles are collected separately.

    Absence of annotation for given SPDX ID is not fatal here and must be
    handled by downstream functions.

    Args:
        parent_sbom_doc: Downloaded used parent image SBOM.
        spdx_id: SPDX ID of the package to inspect.
        annotation_type: The type of annotation to match.

    Returns:
        Matching annotations, or an empty list if the package has no annotation
        with the given type.
    """
    matching_annotations: list[Annotation] = []
    for annotation in get_annotations_by_spdx_id(parent_sbom_doc, spdx_id):
        try:
            parsed = KonfluxAnnotationManager.parse(annotation)
        except AnnotationParseError:
            LOGGER.warning(
                "[Parent image content] Annotation '%s' from parent SBOM '%s' "
                "has a comment that could not be parsed as a Konflux annotation: "
                "'%s'.",
                annotation.spdx_id,
                parent_sbom_doc.creation_info.name,
                annotation.annotation_comment,
            )
            continue
        if parsed is not None and isinstance(parsed, annotation_type):
            matching_annotations.append(annotation)
    return matching_annotations


def _relationship_has_package_endpoints(
    relationship: Relationship,
    package_spdx_ids: set[str],
    file_spdx_ids: set[str],
) -> bool:
    """
    Return whether both endpoints identify packages in the SBOM.

    Contextualization collects package-to-package relationships only. A
    `package CONTAINS file` relationship is normal Syft evidence and is
    silently skipped. Other malformed `CONTAINS` relationships are skipped
    with a warning. Invalid image relationships are rejected.

    Called only for relationship types selected by `ContentKind`.

    Args:
        relationship: SPDX relationship to validate.
        package_spdx_ids: SPDX IDs of packages present in the SBOM.
        file_spdx_ids: SPDX IDs of files present in the SBOM.

    Returns:
        `True` when both relationship endpoints identify existing packages.
        `False` when the relationship is `package CONTAINS file` or another
        `CONTAINS` shape outside the contextual ownership model. Raises
        `SBOMError` when a non-`CONTAINS` image relationship has a non-package
        endpoint.
    """
    if (
        relationship.spdx_element_id in package_spdx_ids
        and relationship.related_spdx_element_id in package_spdx_ids
    ):
        return True

    if relationship.relationship_type is RelationshipType.CONTAINS:
        if (
            relationship.spdx_element_id in package_spdx_ids
            and relationship.related_spdx_element_id in file_spdx_ids
        ):
            # package CONTAINS file is a valid and prevalent SPDX relationship
            # in Syft evidence, but it is outside the package-level
            # contextualization scope.
            return False
        # Other CONTAINS relationship shapes are outside the ownership model used
        # for contextualization. Skip them, but make them observable.
        LOGGER.warning(
            "[Parent image content] Skipping invalid CONTAINS relationship: "
            "%s CONTAINS %s.",
            relationship.spdx_element_id,
            relationship.related_spdx_element_id,
        )
        return False
    # Remaining ContentKind relationship types describe image packages and require
    # both endpoints to identify packages.
    invalid_endpoints = [
        spdx_id
        for spdx_id in (
            relationship.spdx_element_id,
            relationship.related_spdx_element_id,
        )
        if spdx_id not in package_spdx_ids
    ]
    raise SBOMError(
        "[Parent image content] Invalid image relationship "
        f"'{relationship.relationship_type.name}': both endpoints must "
        "identify packages; invalid endpoint SPDX ID(s): "
        f"{invalid_endpoints}."
    )


def _validate_relationship_cardinality_for_content_kind(
    sbom_doc: Document,
    content_items: list[ContentItem],
    kind: ContentKind,
) -> None:
    """
    Validate relationship cardinality for packages within a content kind.

    Repeated ``subject + relationship type + target`` triplets in one document
    are logged as warnings. They represent one logical edge and count once for
    cardinality.

    Cardinality is checked separately for the package endpoint selected by the
    content kind. Multiple distinct relationships of the selected type for one
    endpoint form a one-to-many or many-to-one edge. They are accepted only
    when the content kind allows multiple relationships per endpoint.

    Args:
        sbom_doc: SBOM document containing the relationships.
        content_items: Content items to inspect.
        kind: Content kind defining whether multiple relationships are allowed.

    Raises:
        SBOMError: If a package participates in multiple disallowed
            relationships.
    """
    distinct_relationships_by_endpoint: dict[str, list[Relationship]] = {}
    for item in _warn_and_deduplicate_identical_relationships(
        sbom_doc, content_items, kind
    ):
        distinct_relationships_by_endpoint.setdefault(item.package.spdx_id, []).append(
            item.relationship
        )

    if kind.allows_multiple_relationships_per_endpoint:
        return

    endpoint_relationship_cardinality_violations = {
        package_spdx_id: relationships
        for package_spdx_id, relationships in (
            distinct_relationships_by_endpoint.items()
        )
        if len(relationships) > 1
    }
    if not endpoint_relationship_cardinality_violations:
        return

    if kind.relationship_type is RelationshipType.CONTAINS:
        details = "; ".join(
            f"{package_spdx_id}: "
            + ", ".join(
                f"{relationship.spdx_element_id} CONTAINS "
                f"{relationship.related_spdx_element_id}"
                for relationship in relationships
            )
            for package_spdx_id, relationships in (
                endpoint_relationship_cardinality_violations.items()
            )
        )
        raise SBOMError(
            "[Parent image content] Multiple CONTAINS relationships found "
            f"for content packages: {details}. Document: "
            f"{sbom_doc.creation_info.document_namespace}."
        )

    details = "; ".join(
        f"{package_spdx_id}: {len(relationships)} relationships"
        for package_spdx_id, relationships in (
            endpoint_relationship_cardinality_violations.items()
        )
    )
    raise SBOMError(
        "[Parent image content] Multiple relationships found for image "
        f"packages in content kind '{kind.name}': {details}."
        f" Document: {sbom_doc.creation_info.document_namespace}."
    )


def _warn_and_deduplicate_identical_relationships(
    sbom_doc: Document,
    content_items: list[ContentItem],
    kind: ContentKind,
) -> list[ContentItem]:
    """
    Warn about identical relationship triplets and return their first occurrences.

    An identical subject, relationship type, and target represents one logical
    edge, even when it is repeated in an SBOM and thus this does not represent
    ambiguity for Contextual SBOM. The returned items therefore contain each
    triplet once for subsequent subject-relationship or relationship-target
    cardinality validation.

    Args:
        sbom_doc: SBOM document containing the relationships.
        content_items: Content items to inspect.
        kind: Content kind used in the warning.

    Returns:
        Content items with duplicate relationship triplets removed.
    """
    relationship_triplet_occurrences: Counter[
        tuple[str, RelationshipType, str | SpdxNoAssertion | SpdxNone]
    ] = Counter()
    unique_content_items: list[ContentItem] = []
    for item in content_items:
        relationship = item.relationship
        relationship_triplet = (
            relationship.spdx_element_id,
            relationship.relationship_type,
            relationship.related_spdx_element_id,
        )
        relationship_triplet_occurrences[relationship_triplet] += 1
        if relationship_triplet_occurrences[relationship_triplet] == 1:
            unique_content_items.append(item)

    for (
        subject,
        relationship_type,
        target,
    ), occurrence_count in relationship_triplet_occurrences.items():
        if occurrence_count > 1:
            LOGGER.warning(
                "[Parent image content] Identical relationship triplet found for "
                "content kind '%s': %s %s %s (%s occurrences). It is counted "
                "once for cardinality. Document: %s",
                kind.name,
                subject,
                relationship_type.name,
                target,
                occurrence_count,
                sbom_doc.creation_info.document_namespace,
            )

    return unique_content_items


def _collect(
    sbom_doc: Document,
    kind: ContentKind,
) -> list[ContentItem]:
    """
    Collect packages with relationships of the given kind that point to them.

    All matching relationships pointing to packages are preserved. Whether a
    package may participate in multiple relationships is validated by the
    caller according to the collected content kind.

    Args:
        sbom_doc: SBOM document to inspect (packages and relationships are read).
        kind: Declarative description of the content kind to collect.

    Returns:
        Content items matching the kind.
    """
    package_spdx_ids = {pkg.spdx_id for pkg in sbom_doc.packages}
    file_spdx_ids = {file.spdx_id for file in sbom_doc.files}
    rel_index: dict[str, list[Relationship]] = {}
    for candidate_rel in sbom_doc.relationships:
        if candidate_rel.relationship_type != kind.relationship_type:
            continue
        if not _relationship_has_package_endpoints(
            candidate_rel,
            package_spdx_ids,
            file_spdx_ids,
        ):
            continue
        rel_index.setdefault(
            getattr(candidate_rel, kind.relationship_end.value), []
        ).append(candidate_rel)

    content_items: list[ContentItem] = []
    for pkg in sbom_doc.packages:
        content_items.extend(
            ContentItem(pkg, relationship)
            for relationship in rel_index.get(pkg.spdx_id, [])
        )

    return content_items


def collect_image_items(
    sbom_doc: Document,
    kind: ContentKind,
) -> list[ImageItem]:
    """
    Collect image package items based on annotation kind.

    May return multiple items or empty list; callers need to handle output.

    Args:
        sbom_doc: SBOM document to inspect.
        kind: Declarative description of the (annotation-carrying) content kind.

    Returns:
        List of Image items with matching annotations. Each item contains the
        package, its matching relationship, and all annotations describing the
        image's roles for this content kind.

    """
    assert kind.annotation_type is not None, (
        "collect_image_items requires a kind with an annotation type"
    )
    collected_items = _collect(sbom_doc, kind)
    _validate_relationship_cardinality_for_content_kind(sbom_doc, collected_items, kind)

    items: list[ImageItem] = []
    for item in collected_items:
        annotations = get_annotations_by_spdx_id_filter_by_type(
            sbom_doc, item.package.spdx_id, kind.annotation_type
        )
        if not annotations:
            continue
        items.append(ImageItem(item.package, item.relationship, annotations))

    return items


def collect_package_items(
    sbom_doc: Document,
) -> list[ContentItem]:
    """
    Collect content packages (CONTAINS) of the SBOM document.

    Each content package may be the target of only one distinct package-level
    `CONTAINS` relationship. Multiple distinct owners are invalid because the
    package origin cannot be determined.

    Args:
        sbom_doc: SBOM document to inspect.

    Returns:
        Content items.
    """
    content_items = _collect(sbom_doc, CONTENT_PACKAGE)
    _validate_relationship_cardinality_for_content_kind(
        sbom_doc, content_items, CONTENT_PACKAGE
    )

    return content_items
