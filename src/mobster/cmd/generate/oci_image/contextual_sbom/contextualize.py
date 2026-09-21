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
from dataclasses import dataclass
from enum import Enum
from typing import Any

from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.contextual_sbom.logging import MatchingStatistics
from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    ComponentRelationshipResolver,
)
from mobster.cmd.generate.oci_image.spdx_utils import (
    AnnotationAncestorImage,
    AnnotationBaseImage,
    AnnotationParseError,
    KonfluxAnnotationManager,
    find_spdx_root_packages_spdxid,
    get_annotations_by_spdx_id,
)
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci import cosign

LOGGER = logging.getLogger(__name__)


class RelationshipEnd(str, Enum):
    """
    Which endpoint of a relationship holds the spdx_id of the collected image
    package.
    """

    SUBJECT = "spdx_element_id"
    TARGET = "related_spdx_element_id"


@dataclass(frozen=True)
class ContentKind:
    """
    Instance is eclarative description of one kind of content searched in SBOM.
    Most kinds are describing image content inherited from the used parent
    (base and ancestor images) for supplying it to the component, while the
    plain content-package kind is collected from either the parent or the
    component for package matching.

    A kind is identified by
     - a human-readable name,
     - relationship type,
     - relationship end that points to package of interest,
     - annotation type that package must carry (None for plain content packages).

    Instances drive collectors `collect_package_items` and `collect_image_items`
    """

    name: str
    relationship_type: RelationshipType
    relationship_end: RelationshipEnd
    annotation_type: type[AnnotationBaseImage] | type[AnnotationAncestorImage] | None


# parent DESCENDANT_OF grandparent (grandparent
# annotated is_base_image in downloaded parent SBOM)
PARENT_BASE_IMAGE = ContentKind(
    "parent base image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.TARGET,
    AnnotationBaseImage,
)
# grandparent DESCENDANT_OF grandgrandparent (deeper
# ancestor present if parent is contextualized)
PARENT_ANCESTOR_IMAGE = ContentKind(
    "parent ancestor image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.TARGET,
    AnnotationAncestorImage,
)
# legacy grandparent BUILD_TOOL_OF parent (grandparent
# from pre-mobster era)
LEGACY_GRANDPARENT_IMAGE = ContentKind(
    "legacy grandparent image",
    RelationshipType.BUILD_TOOL_OF,
    RelationshipEnd.SUBJECT,
    AnnotationBaseImage,
)
# component CONTAINS package (plain content package, no annotation type)
CONTENT_PACKAGE = ContentKind(
    "content package", RelationshipType.CONTAINS, RelationshipEnd.TARGET, None
)


@dataclass
class ImageItem:
    """
    A resolved image package, with annotation and relationship, modified and
    ready to be supplied to component SBOM.
    """

    package: Package
    relationship: Relationship
    annotation: Annotation


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
        LOGGER.info("Contextual mechanism won't be used, there is no parent image.")
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
        The grandparent image item with its package and annotation updated and
        a new `DESCENDANT_OF` relationship connecting the component's parent
        to the grandparent.
    """
    grandparent_package = grandparent_item.package
    grandparent_annotation = grandparent_item.annotation

    # package modification
    grandparent_package.files_analyzed = False

    # relationship modification
    modified_rel = Relationship(
        spdx_element_id=parent_spdx_id_from_component,
        relationship_type=RelationshipType.DESCENDANT_OF,
        related_spdx_element_id=grandparent_package.spdx_id,
    )

    # annotation modification
    if grandparent_annotation.annotation_comment:
        grandparent_annotation.annotation_comment = (
            grandparent_annotation.annotation_comment.replace(
                "is_base_image", "is_ancestor_image"
            )
        )

    return ImageItem(
        package=grandparent_package,
        relationship=modified_rel,
        annotation=grandparent_annotation,
    )


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
        PARENT_BASE_IMAGE,
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
            LEGACY_GRANDPARENT_IMAGE,
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
                "scratch), it is malformed or the downloaded SBOM"
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
        PARENT_ANCESTOR_IMAGE,
    )
    return [
        process_grandparent_item(
            grandparent_item[0],
            parent_spdx_id_from_component,
        )
    ] + ancestor_image_items


def get_annotation_by_spdx_id_filter_by_type(
    parent_sbom_doc: Document,
    spdx_id: str,
    annotation_type: (type[AnnotationBaseImage] | type[AnnotationAncestorImage]),
) -> Annotation | None:
    """
    Returns the annotation with the given Konflux annotation type for a package
    SPDXID, or None.

    Absence of annotation for given SPDXID is not fatal here and must be
    handled by downstream functions.

    Args:
        parent_sbom_doc: Downloaded used parent image SBOM.
        spdx_id: SPDX ID of the package to inspect.
        annotation_type: The type of annotation to match.

    Returns:
        The matching annotation, or None if the package has no annotation with
        the given type.
    """
    for annotation in get_annotations_by_spdx_id(parent_sbom_doc, spdx_id):
        try:
            parsed = KonfluxAnnotationManager.parse(annotation)
        except AnnotationParseError:
            LOGGER.warning(
                "[Parent image content] Annotation comment '%s' could not be "
                "parsed as a Konflux annotation.",
                annotation.annotation_comment,
            )
            continue
        if parsed is not None and isinstance(parsed, annotation_type):
            return annotation
    return None


def _collect(
    sbom_doc: Document,
    kind: ContentKind,
) -> list[tuple[Package, Relationship]]:
    """
    Pair each package with the relationship of the given kind that points to it.

    Args:
        sbom_doc: SBOM document to inspect (packages and relationships are read).
        kind: Declarative description of the content kind to collect.

    Returns:
        List of (package, relationship) pairs matching the kind.
    """
    # build relationship index based on targeted package (relationship_end)
    rel_index: dict[str, Relationship] = {}
    for candidate_rel in sbom_doc.relationships:
        if candidate_rel.relationship_type != kind.relationship_type:
            continue
        relationship_end_spdx_id = getattr(candidate_rel, kind.relationship_end.value)
        if isinstance(relationship_end_spdx_id, str):
            # If the SBOM is valid this should never happen because
            # relationship end SPDX ID is expected to be unique
            if relationship_end_spdx_id in rel_index:
                raise SBOMError(
                    "[Parent image content] Multiple"
                    " relationships found for content kind "
                    f"'{kind.name}' ({kind.relationship_type.name}, "
                    f"{kind.relationship_end.value}) and SPDX ID "
                    f"'{relationship_end_spdx_id}'."
                )
            rel_index[relationship_end_spdx_id] = candidate_rel

    pkg_rel_pairs: list[tuple[Package, Relationship]] = []
    for pkg in sbom_doc.packages:
        rel = rel_index.get(pkg.spdx_id)
        if rel is None:
            continue
        pkg_rel_pairs.append((pkg, rel))

    return pkg_rel_pairs


def collect_package_items(
    sbom_doc: Document,
) -> list[tuple[Package, Relationship]]:
    """
    Collect content packages (CONTAINS) of the SBOM document.

    Args:
        sbom_doc: SBOM document to inspect.

    Returns:
        List of (package, relationship) pairs.
    """
    return _collect(sbom_doc, CONTENT_PACKAGE)


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
        List of Image items with a non-`None` annotation. Each item contains the
        package, its matching relationship, and the annotation describing
        image's role.
    """
    assert kind.annotation_type is not None, (
        "collect_image_items requires a kind with an annotation type"
    )
    items: list[ImageItem] = []
    for pkg, rel in _collect(sbom_doc, kind):
        annotation = get_annotation_by_spdx_id_filter_by_type(
            sbom_doc, pkg.spdx_id, kind.annotation_type
        )
        if annotation is None:
            continue
        items.append(ImageItem(pkg, rel, annotation))

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
    2. Ancestor image subtree: supply the parent's grandparent and deeper
       ancestor image packages, together with their relationships and
       annotations, to the component. Relationships are aligned with the
       component's parent name where needed.

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

    # Step 2: resolve and supply grandparent and ancestor image packages
    # from parent to component
    grandparent_and_ancestors = get_grandparent_and_ancestor_items_from_used_parent(
        parent_sbom_doc, parent_spdx_id_from_component
    )
    resolver.supply_image_packages(grandparent_and_ancestors)

    stats.log_summary_debug()

    return component_sbom_doc
