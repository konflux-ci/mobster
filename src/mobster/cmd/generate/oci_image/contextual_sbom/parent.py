"""
Module accessing used parent image content in SBOMs and
modifying component content to indicate relationships with parent.

component - the currently contextualized image SBOM
used parent (SBOM) - base image (SBOM) of currently contextualized component
grandparent (SBOM) - used parent's base image (SBOM)
ancestor - base image of the grandparent (and further)
item - image package, relevant relationship and image package annotation
       grouped together
"""

import logging
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    ANCESTOR_IMAGE,
    BASE_IMAGE,
    BUILDER_IMAGE,
    CONTENT_PACKAGE,
    INTERMEDIATE_IMAGE,
    LEGACY_BASE_IMAGE,
    ContentKind,
)
from mobster.cmd.generate.oci_image.contextual_sbom.logging import MatchingStatistics
from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    ComponentRelationshipResolver,
)
from mobster.cmd.generate.oci_image.spdx_utils import (
    AnnotationAncestorImage,
    AnnotationBaseImage,
    AnnotationBuilderImage,
    AnnotationIntermediateImage,
    AnnotationParseError,
    KonfluxAnnotationManager,
    find_spdx_root_packages_spdxid,
    get_annotations_by_spdx_id,
)
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci import cosign

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


async def download_parent_image_sbom(
    parent_image: Image | None, arch: str
) -> dict[str, Any] | None:
    """
    Downloads parent SBOM. First tries to download arch-specific SBOM, then image index
    as a fallback.
    Args:
        parent_image: Which image SBOM to download.
        arch: Architecture of the target system.
            Will be the same as the current runtime arch.
    Returns:
        The found SBOM or `None` if the SBOM is in CycloneDX format or not found.
    """
    if not parent_image:
        LOGGER.info(
            "[Parent image content] Contextual mechanism "
            "won't be used, there is no parent image."
        )
        return None
    image_or_index = await Image.from_repository_digest_manifest(
        parent_image.repository, parent_image.digest
    )
    actual_parent_image = image_or_index
    if isinstance(image_or_index, IndexImage):
        for child in image_or_index.children:
            if child.arch == arch:
                actual_parent_image = child
                break
    if isinstance(actual_parent_image, IndexImage):
        LOGGER.debug(
            "[Parent image content] Only the index image of parent was "
            "found for ref %s and arch %s",
            parent_image.reference,
            arch,
        )
    else:
        LOGGER.debug(
            "[Parent image content] The specific arch was successfully "
            "located for ref %s and arch %s",
            parent_image.reference,
            arch,
        )

    cosign_client = cosign.AnonymousFetcher()
    try:
        sbom = await cosign_client.fetch_sbom(actual_parent_image)
    except SBOMError:
        LOGGER.info(
            "[Parent image content] Contextual mechanism won't be used, "
            "there is no parent image SBOM."
        )
        return None
    if not sbom.format.is_spdx2():
        LOGGER.info(
            "[Parent image content] Contextual mechanism won't be used, "
            "SBOM format is not supported for this workflow."
        )
        return None
    LOGGER.info(
        "[Parent image content] Contextual workflow will be used. Parent SBOM "
        "used for contextualization: %s",
        sbom.doc["documentNamespace"],
    )
    return sbom.doc


def get_parent_spdx_id_from_component(component_sbom_doc: Document) -> str:
    """
    Obtains the component's used parent image SPDXID from DESCENDANT_OF
    relationship. Component SBOM is created before contextualization
    and bears single DESCENDANT_OF relationship pointing to its parent.

    Acquired parent's SPDXID is used to align relationships
    in the final component SBOM;
    - modification of relationships present in component:
        - `component (before package match) CONTAINS package (parent-owned)`
          -> `parent (after package match -> parent name from component) CONTAINS
          package (parent-owned)`
    - modification of relationships inherited from parent to component:
        - `parent (name from parent) DESCENDANT_OF grandparent` ->
          `parent (name from component) DESCENDANT_OF grandparent`
        - `builder BUILD_TOOL_OF parent (name from parent)` ->
          `builder BUILD_TOOL_OF parent (name from component)`
        - `grandparent BUILD_TOOL_OF parent (name from parent)` ->
          `parent (name from component) DESCENDANT_OF grandparent`

    Absence of the DESCENDANT_OF relationship (contextual workflow is guarded
    against contextualization of the images built FROM scratch or oci-archive)
    or multiple relationships in non-contextualized component SBOM indicate
    that mobster non-contextual SBOM generation that precedes this contextual
    workflow is broken and generated SBOM cannot proceed to contextualization.

    Args:
        component_sbom_doc: Non-contextualized component SBOM with
            DESCENDANT_OF relationship pointing to used parent image.

    Returns:
        SPDX ID of the parent image defined by this component.
        It must always be present assuming that _execute_contextual_workflow
        is skipping parent contextualization for FROM scratch or oci-archive
        images.

    Raises:
        SBOMError: If the passed SBOM does not contain DESCENDANT_OF
            relationship or contains multiple DESCENDANT_OF relationships.
    """
    parent_name = []
    for relationship in component_sbom_doc.relationships:
        if relationship.relationship_type == RelationshipType.DESCENDANT_OF:
            parent_name.append(relationship.related_spdx_element_id)

    if not parent_name:
        raise SBOMError(
            "[Parent image content] Passed component SBOM does not contain any "
            "DESCENDANT_OF "
            "relationship. Parent name cannot be determined."
        )

    if len(parent_name) > 1:
        raise SBOMError(
            "[Parent image content] Passed component SBOM contains multiple "
            "DESCENDANT_OF "
            "relationships. Parent name cannot be determined."
        )

    parent_spdx_id = parent_name[0]
    if not isinstance(parent_spdx_id, str):
        raise SBOMError(
            "[Parent image content] DESCENDANT_OF relationship does not "
            "reference a concrete parent SPDX ID."
        )

    return parent_spdx_id


def process_grandparent_item(
    grandparent_item: ImageItem,
    parent_spdx_id_from_component: str,
) -> ImageItem:
    """
    Converts a grandparent item (base image of the used parent) into an
    ancestor item to be supplied to the component SBOM.

    Image package:
    The ancestor (grandparent) is only an image reference, not an image
    whose files were scanned in the current build (unlike the component
    itself). That is why its files_analyzed must be False.

    Relationship:
    Handles both parent SBOM shapes uniformly;
    - new:    `parent DESCENDANT_OF grandparent`
    - legacy: `grandparent BUILD_TOOL_OF parent (pre-mobster, converted here)`
    Output is always `parent (name from component) DESCENDANT_OF grandparent`.
    The subject uses the parent name as referenced by the component
    (parent_spdx_id_from_component) so it aligns with the component's
    relationships.

    Annotation:
    The grandparent is re-annotated to is_ancestor_image because, from the
    component's point of view, it is an ancestor, not its base image.
    Component SBOM already indicates its parent with existing
    `component DESCENDANT_OF parent`. The change also matters when this
    component is later used as a base image for another build: during
    that contextualization its ancestors must already be marked
    is_ancestor_image.

    Args:
        grandparent_item: Original grandparent image item from parent SBOM.
        parent_spdx_id_from_component: SPDX ID of the parent image as referenced
            by the component SBOM.

    Returns:
        The grandparent image item with its package and annotations updated and
        a new `DESCENDANT_OF` relationship connecting the component's parent
        to the grandparent.
    """
    grandparent_package = deepcopy(grandparent_item.package)
    grandparent_annotations = deepcopy(grandparent_item.annotations)

    # package modification
    grandparent_package.files_analyzed = False

    # relationship modification
    modified_rel = Relationship(
        spdx_element_id=parent_spdx_id_from_component,
        relationship_type=RelationshipType.DESCENDANT_OF,
        related_spdx_element_id=grandparent_package.spdx_id,
    )

    # annotation modification
    for annotation in grandparent_annotations:
        if "is_base_image" in annotation.annotation_comment:
            annotation.annotation_comment = annotation.annotation_comment.replace(
                "is_base_image", "is_ancestor_image"
            )

    return ImageItem(
        package=grandparent_package,
        relationship=modified_rel,
        annotations=grandparent_annotations,
    )


def process_builder_items(
    builder_items: list[ImageItem],
    parent_spdx_id_from_component: str,
    parent_root_packages: list[str],
) -> list[ImageItem]:
    """
    Aligns builder image items (the builder subtrees belonging to the component's
    parent and all of the component's known ancestors) with the component's
    relationships.

    A builder is attached to the image it builds (used parent or ancestors) via
    BUILD_TOOL_OF. Builders of the used parent itself point at the parent root
    (`builder BUILD_TOOL_OF parent`); that target must be renamed to the parent
    name as referenced by the component
    (`builder BUILD_TOOL_OF parent (name from component)`). Builders of deeper
    ancestors already reference a correctly named ancestor
    (`builder BUILD_TOOL_OF ancestor`) and are passed through unchanged (those
    will point on ancestors collected by
    get_grandparent_and_ancestor_items_from_used_parent later also supplied to
    final component SBOM)

    Args:
        builder_items: Builder image items collected across the whole
            ancestor chain of the used parent.
        parent_spdx_id_from_component: SPDX ID of the parent as referenced by
            the component.
        parent_root_packages: SPDX IDs of the used parent's root packages; a
            BUILD_TOOL_OF target in this set marks a builder of the parent
            itself and is renamed.

    Returns:
        The builder image items with parent-root `BUILD_TOOL_OF` targets
        renamed to the component's parent name; all other items unchanged.
    """
    modified_builder_items: list[ImageItem] = []
    for item in builder_items:
        if item.relationship.related_spdx_element_id in parent_root_packages:
            renamed_rel = Relationship(
                spdx_element_id=item.relationship.spdx_element_id,
                relationship_type=item.relationship.relationship_type,
                related_spdx_element_id=parent_spdx_id_from_component,
            )
            modified_builder_items.append(
                ImageItem(
                    package=item.package,
                    relationship=renamed_rel,
                    annotations=item.annotations,
                )
            )
        else:
            modified_builder_items.append(item)
    return modified_builder_items


def get_grandparent_and_ancestor_items_from_used_parent(
    parent_sbom_doc: Document,
    parent_spdx_id_from_component: str,
) -> list[ImageItem]:
    """
    Obtain the grandparent image item of the component from the used parent and, if the
    used parent is contextualized, obtain all of its deeper ancestor items. Grandparent
    item is modified for later supply to the component SBOM.

    The grandparent relationship is `parent DESCENDANT_OF grandparent`, or the
    legacy `grandparent BUILD_TOOL_OF parent` for parents produced in the
    pre-mobster era (converted to DESCENDANT_OF here). Deeper ancestors
    (`grandparent DESCENDANT_OF grandgrandparent`, ...) are passed through as
    collected. When no grandparent can be determined (built from scratch,
    oci-archive, malformed or non-konflux SBOM), an empty list is returned.

    Args:
        parent_sbom_doc: Downloaded used parent image SBOM.
        parent_spdx_id_from_component: SPDX ID of the used parent as referenced
            by the component SBOM.

    Returns:
        List of grandparent and ancestor items, or an empty list if no
        grandparent can be determined.

    Raises:
        SBOMError: If the parent SBOM contains more than one base image item
            (new or legacy shape).
    """
    # New SBOM (mobster era - contextualized or non-contextualized):
    # `parent DESCENDANT_OF grandparent`, with the grandparent image
    # package annotated as is_base_image
    grandparent_item = collect_image_items(
        parent_sbom_doc,
        BASE_IMAGE,
    )
    if len(grandparent_item) > 1:
        raise SBOMError(
            "[Parent image content] Multiple base image items found in "
            "downloaded parent SBOM (produced by mobster) "
            f"{parent_sbom_doc.creation_info.name}. Only one is expected."
        )

    # Legacy SBOM (pre-mobster era): `grandparent BUILD_TOOL_OF parent`
    # with the grandparent image package annotated as is_base_image.
    # When no grandparent can be determined at all (built from scratch,
    # oci-archive, malformed or non-konflux SBOM), there is nothing to supply.
    #
    # TO DO: once legacy pre-mobster SBOMs are gone (or rare enough to drop
    # support for), enforce mobster provenance right after download by
    # checking for a `Tool: Mobster-<version>` creator, and skip/fail
    # otherwise. This should be done after log analysis (Legacy grandparent
    # detected). Doing so would make the whole contextual SBOM workflow more
    # deterministic - the parent input would be guaranteed to be mobster-produced,
    # this branch can be removed keeping only reduced "cannot determine parent"
    # log from this branch from three cases (from scratch / oci-archive, malformed,
    # non-konflux SBOM) only to "built from scratch / oci-archive".
    if not grandparent_item:
        legacy_grandparent_item = collect_image_items(
            parent_sbom_doc,
            LEGACY_BASE_IMAGE,
        )

        if len(legacy_grandparent_item) > 1:
            raise SBOMError(
                "[Parent image content] Multiple base image items found in "
                "downloaded parent SBOM (non-mobster produced) "
                f"{parent_sbom_doc.creation_info.name}. Only one is expected."
            )

        if not legacy_grandparent_item:
            LOGGER.info(
                "[Parent image content] Cannot determine parent of the "
                "downloaded parent image SBOM. It either does "
                "not exist (it was an oci-archive or the image is built from "
                "scratch), it is malformed or the downloaded SBOM "
                "is not sourced from konflux."
            )
            return []

        # Legacy (pre-mobster) parent: `grandparent BUILD_TOOL_OF parent`.
        LOGGER.info("[Parent image content] Legacy grandparent detected.")
        return [
            process_grandparent_item(
                legacy_grandparent_item[0],
                parent_spdx_id_from_component,
            )
        ]

    LOGGER.info("[Parent image content] Mobster-produced grandparent detected.")
    # Contextualized parent SBOM may contain
    # ancestors from previous contextualizations
    ancestor_image_items = collect_image_items(
        parent_sbom_doc,
        ANCESTOR_IMAGE,
    )
    return [
        process_grandparent_item(
            grandparent_item[0],
            parent_spdx_id_from_component,
        )
    ] + ancestor_image_items


def get_annotations_by_spdx_id_filter_by_type(
    parent_sbom_doc: Document,
    spdx_id: str,
    annotation_type: (
        type[AnnotationBaseImage]
        | type[AnnotationAncestorImage]
        | type[AnnotationBuilderImage]
        | type[AnnotationIntermediateImage]
    ),
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


def _collect(
    sbom_doc: Document,
    kind: ContentKind,
) -> list[tuple[Package, Relationship]]:
    """
    Pair each package with the relationship of the given kind that points to it.

    All matching relationships pointing to packages are preserved. Whether a
    package may participate in multiple relationships is validated by the
    caller according to the collected content kind.

    Args:
        sbom_doc: SBOM document to inspect (packages and relationships are read).
        kind: Declarative description of the content kind to collect.

    Returns:
        List of (package, relationship) pairs matching the kind.
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

    pkg_rel_pairs: list[tuple[Package, Relationship]] = []
    for pkg in sbom_doc.packages:
        pkg_rel_pairs.extend((pkg, rel) for rel in rel_index.get(pkg.spdx_id, []))

    return pkg_rel_pairs


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


def collect_package_items(
    sbom_doc: Document,
) -> list[tuple[Package, Relationship]]:
    """
    Collect content packages (CONTAINS) of the SBOM document.

    Each content package may be the target of only one distinct package-level
    `CONTAINS` relationship. Multiple distinct owners are invalid because the
    package origin cannot be determined.

    Args:
        sbom_doc: SBOM document to inspect.

    Returns:
        List of (package, relationship) pairs.
    """
    package_items = _collect(sbom_doc, CONTENT_PACKAGE)
    _validate_relationship_cardinality_for_content_kind(
        sbom_doc, package_items, CONTENT_PACKAGE
    )

    return package_items


def _validate_relationship_cardinality_for_content_kind(
    sbom_doc: Document,
    package_items: list[tuple[Package, Relationship]],
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
        package_items: Package and relationship pairs to inspect.
        kind: Content kind defining whether multiple relationships are allowed.

    Raises:
        SBOMError: If a package participates in multiple disallowed
            relationships.
    """
    distinct_relationships_by_endpoint: dict[str, list[Relationship]] = {}
    for package, relationship in _warn_on_identical_relationships(
        sbom_doc, package_items, kind
    ):
        distinct_relationships_by_endpoint.setdefault(package.spdx_id, []).append(
            relationship
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


def _warn_on_identical_relationships(
    sbom_doc: Document,
    package_items: list[tuple[Package, Relationship]],
    kind: ContentKind,
) -> list[tuple[Package, Relationship]]:
    """
    Warn about identical relationship triplets and return their first occurrences.

    An identical subject, relationship type, and target represents one logical
    edge, even when it is repeated in an SBOM and thus this does not represent
    ambiguity for Contextual SBOM. The returned items therefore contain each
    triplet once for subsequent subject-relationship or relationship-target
    cardinality validation.

    Args:
        sbom_doc: SBOM document containing the relationships.
        package_items: Package and relationship pairs to inspect.
        kind: Content kind used in the warning.

    Returns:
        Package and relationship pairs with duplicate triplets removed.
    """
    relationship_triplet_occurrences: Counter[
        tuple[str, RelationshipType, str | SpdxNoAssertion | SpdxNone]
    ] = Counter()
    unique_package_items: list[tuple[Package, Relationship]] = []
    for package_item in package_items:
        relationship = package_item[1]
        relationship_triplet = (
            relationship.spdx_element_id,
            relationship.relationship_type,
            relationship.related_spdx_element_id,
        )
        relationship_triplet_occurrences[relationship_triplet] += 1
        if relationship_triplet_occurrences[relationship_triplet] == 1:
            unique_package_items.append(package_item)

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

    return unique_package_items


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
    for pkg, rel in collected_items:
        annotations = get_annotations_by_spdx_id_filter_by_type(
            sbom_doc, pkg.spdx_id, kind.annotation_type
        )
        if not annotations:
            continue
        items.append(ImageItem(pkg, rel, annotations))

    return items


async def map_parent_to_component_and_update_component(
    parent_sbom_doc: Document,
    component_sbom_doc: Document,
    parent_spdx_id_from_component: str,
) -> Document:
    """
    Contextualize the component SBOM against its downloaded used parent SBOM.

    Workflow consists two steps, both mutating the component SBOM in place:

    1. Content packages: match the parent's content packages against the
       component's and, for every match, rewrite the component's CONTAINS
       relationship so it points at the parent (name from component) or the
       grandparent that actually owns the package (inherit relationship).
       Matching statistics are collected for later logging.
    2. Image subtree: supply the parent's image packages (with their
       relationships and annotations) to the component - the grandparent and
       any deeper ancestors, plus the builder and intermediate images of the
       parent and its ancestors. Relationships are aligned with the component's
       parent name where needed.

    Args:
        parent_sbom_doc: Downloaded used parent image SBOM
            (can be contextualized or not).
        component_sbom_doc: The component SBOM to be contextualized.
        parent_spdx_id_from_component: SPDX ID of the used parent as referenced
            by the component SBOM (determined at component SBOM generation).

    Returns:
        The contextualized component SBOM (the same object, modified in place).
    """
    parent_root_packages = await find_spdx_root_packages_spdxid(parent_sbom_doc)
    if not parent_root_packages:
        raise SBOMError(
            "[Parent image content] Parent SBOM cannot be used for "
            "contextualization: "
            f"{parent_sbom_doc.creation_info.name}: no SPDX root relationship "
            "was found."
        )

    # Step 1: Map packages between parent and component and update origins
    parent_packages = collect_package_items(parent_sbom_doc)
    component_packages = collect_package_items(component_sbom_doc)

    stats = MatchingStatistics()
    # Set parent and component SBOM references for logging
    stats.parent_sbom_reference = parent_sbom_doc.creation_info.document_namespace
    stats.component_sbom_reference = component_sbom_doc.creation_info.document_namespace

    # Record total amount of packages both in parent and component
    stats.record_component_packages(component_packages)
    stats.record_parent_packages(parent_packages)

    resolver = ComponentRelationshipResolver(
        component_packages,
        parent_sbom_doc,
        component_sbom_doc,
        stats,
    )

    resolver.resolve_component_relationships(
        parent_packages, parent_spdx_id_from_component, parent_root_packages
    )

    # Step 2: resolve and supply image packages (grandparent, ancestors and builders
    # and intermediates of parent and ancestors) from parent to component
    # TO DO: Validate the complete image graph, ensuring that the image chain
    # from the root image to the furthest ancestor is continuous and has no
    # missing links.
    grandparent_and_ancestors = get_grandparent_and_ancestor_items_from_used_parent(
        parent_sbom_doc, parent_spdx_id_from_component
    )
    parent_and_ancestors_builder_items = process_builder_items(
        collect_image_items(
            parent_sbom_doc,
            BUILDER_IMAGE,
        ),
        parent_spdx_id_from_component,
        parent_root_packages,
    )
    parent_and_ancestors_intermediate_items = collect_image_items(
        parent_sbom_doc,
        INTERMEDIATE_IMAGE,
    )
    resolver.supply_image_packages(
        grandparent_and_ancestors
        + parent_and_ancestors_builder_items
        + parent_and_ancestors_intermediate_items
    )

    stats.log_summary_debug()

    return component_sbom_doc
