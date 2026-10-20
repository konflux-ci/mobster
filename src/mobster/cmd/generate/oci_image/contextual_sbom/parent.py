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
from copy import deepcopy
from typing import Any

from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    ADDITIONAL_IMAGE,
    ANCESTOR_IMAGE,
    BASE_IMAGE,
    BUILDER_IMAGE,
    INTERMEDIATE_IMAGE,
    LEGACY_BASE_IMAGE,
)
from mobster.cmd.generate.oci_image.contextual_sbom.item_collection import (
    ImageItem,
    collect_image_items,
    collect_package_items,
)
from mobster.cmd.generate.oci_image.contextual_sbom.logging import MatchingStatistics
from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    ComponentRelationshipResolver,
)
from mobster.cmd.generate.oci_image.spdx_utils import find_spdx_root_packages_spdxid
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci import cosign

LOGGER = logging.getLogger(__name__)


async def download_parent_image_sbom(
    parent_image: Image, arch: str
) -> dict[str, Any] | None:
    """
    Downloads the parent SBOM for the requested architecture.
    Args:
        parent_image: Which image SBOM to download.
        arch: Architecture of the target system.
            Will be the same as the current runtime arch.
    Returns:
        The found SBOM or `None` if no matching architecture, the SBOM is in
        CycloneDX format, or no SBOM is found.
    """
    image_or_index = await Image.from_repository_digest_manifest(
        parent_image.repository, parent_image.digest
    )
    actual_parent_image: Image | None = image_or_index
    if isinstance(image_or_index, IndexImage):
        actual_parent_image = None
        for child in image_or_index.children:
            if child.arch == arch:
                actual_parent_image = child
                break
    if actual_parent_image is None:
        LOGGER.info(
            "[Parent image content] Contextual mechanism won't be used, "
            "no parent image was found for ref %s and arch %s.",
            parent_image.reference,
            arch,
        )
        return None
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
    Aligns builder image items (additional images and builders belonging to
    the component's parent and all of the preceding known ancestors) with
    the component's relationships.

    A builders and additional images are attached to the image that build (used
    parent or ancestors) via BUILD_TOOL_OF. Builders and additional images of
    the used parent itself point at the parent root
    (`builder/additional_image BUILD_TOOL_OF parent_root`); this target must
    be renamed to the parent name as referenced by the component
    (`builder/additional_image BUILD_TOOL_OF parent (name from component)`).
    Builders and additional images of deeper ancestors already reference a
    correctly named ancestor
    (`builder/additional_image BUILD_TOOL_OF ancestor`) and are passed through
    unchanged (those will point on ancestors collected by
    get_grandparent_and_ancestor_items_from_used_parent, later also supplied to
    final component SBOM)

    Args:
        builder_items: Builder and additional image items collected across
            the whole ancestor chain of the used parent.
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

    # Step 2: resolve and supply image packages (grandparent, ancestors,
    # additional images, builders and intermediates of parent and ancestors)
    # from parent to component
    # TO DO: Validate the complete image graph, ensuring that the image chain
    # from the root image to the furthest ancestor is continuous and has no
    # missing links.
    grandparent_and_ancestors = get_grandparent_and_ancestor_items_from_used_parent(
        parent_sbom_doc, parent_spdx_id_from_component
    )
    parent_and_ancestors_builder_items = process_builder_items(
        collect_image_items(parent_sbom_doc, BUILDER_IMAGE)
        + collect_image_items(parent_sbom_doc, ADDITIONAL_IMAGE),
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
