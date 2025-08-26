"""Module accessing and modifying parent image content in SBOMs."""

import json
import logging
from pathlib import Path
from typing import Any

from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import RelationshipType

from mobster.cmd.generate.oci_image.constants import (
    IS_BASE_IMAGE_ANNOTATION,
    ContentType,
)
from mobster.cmd.generate.oci_image.spdx_utils import find_spdx_root_packages_spdxid
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.cosign import CosignClient

LOGGER = logging.getLogger(__name__)


async def get_used_parent_image_from_legacy_sbom(data: Document) -> str | None:
    """
    Identifies SPDXID of the parent image in legacy non-contextual SBOM.
    Counts on legacy marking in the downloaded parent image SBOM.

    Args:
        data: SPDX Document object containing the annotations.
    Returns:
        SPDXID of the parent image if found, `None` otherwise.
    """
    for annotation in data.annotations:
        try:
            if json.loads(annotation.annotation_comment) == IS_BASE_IMAGE_ANNOTATION:
                return annotation.spdx_id
        except json.JSONDecodeError:
            LOGGER.debug(
                "Annotation comment '%s' is not in JSON format.",
                annotation.annotation_comment,
            )

    LOGGER.debug(
        "[Parent image content] Cannot determine parent of the "
        "downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch) or the downloaded SBOM is not sourced from konflux."
    )
    return None


async def convert_to_descendant_of_relationship(
    sbom_doc: Document, grandparent_spdx_id: str
) -> Document:
    """
    This function converts BUILD_TOOL_OF legacy relationship
    of the parent image to the DESCENDANT_OF relationship.

    1. Modifies relationshipType form BUILD_TOOL_OF to DESCENDANT_OF
    2. Flips spdxElementId and relatedSpdxElement

    Args:
        sbom_doc: The SBOM data.
        grandparent_spdx_id: The SPDXID of the targeted relationship to modify.
    Returns:
        The modified SBOM Document with the DESCENDANT_OF relationship set.
    """
    # not filtering a BUILD_TOOL_OF relationship right
    # away here is actually defensive approach and
    # gives us opportunity for more granular error
    # handling in case of inconsistencies in legacy SBOMs
    original_relationships = [
        r for r in sbom_doc.relationships if r.spdx_element_id == grandparent_spdx_id
    ]

    if not original_relationships:
        LOGGER.warning(
            "[Parent image content] Targeted SPDXID %s does not bear any relationship!",
            grandparent_spdx_id,
        )
        return sbom_doc

    if len(original_relationships) > 1:
        LOGGER.warning(
            "[Parent image content] Targeted SPDXID "
            "%s has more than one relationship. "
            "This is not expected, skipping modification.",
            grandparent_spdx_id,
        )
        return sbom_doc
    original_relationship = original_relationships[0]
    original_relationship_type = original_relationship.relationship_type
    if not original_relationship_type == RelationshipType.BUILD_TOOL_OF:
        LOGGER.warning(
            "[Parent image content] Targeted SPDXID %s "
            "does not bear BUILD_TOOL_OF relationship but "
            "%s relationship.",
            grandparent_spdx_id,
            original_relationship_type,
        )
        return sbom_doc
    related_spdxid = original_relationship.related_spdx_element_id
    if isinstance(related_spdxid, str):
        # This is expected to happen every time,
        # but `related_spdx_element_id` is typed as str | None | NOASSERTION
        original_relationship.relationship_type = RelationshipType.DESCENDANT_OF
        original_relationship.spdx_element_id = related_spdxid
        original_relationship.related_spdx_element_id = grandparent_spdx_id
        LOGGER.debug(
            "[%s] Modified relationship_type: from "
            "BUILD_TOOL_OF to DESCENDANT_OF for spdx_element_id=%s",
            ContentType.PARENT.value,
            grandparent_spdx_id,
        )

    return sbom_doc


async def adjust_parent_image_relationship_in_legacy_sbom(
    sbom_doc: Document, grandparent_spdx_id: str | None
) -> Document:
    """
    Identifies packages marked as used parent image in legacy
    SBOM and modifies its relationships accordingly.
    Args:
        sbom_doc: The SBOM data.
        grandparent_spdx_id:
            The SPDXID of the grandparent image of the processed parent image.
    Returns:
        The modified SBOM document with the parent image relationship set
        to DESCENDANT_OF.
    """
    if not grandparent_spdx_id:
        return sbom_doc

    # When DESCENDANT_OF is present SBOM already
    # has properly assigned relationship with its parent
    # so we do not need to modify it.
    # n+1 count of DESCENDANT_OF relationships means that
    # this parent (1) and potentially its parents (n) were
    # already contextualized or at least DESCENDANT_OF
    # relationship has been set for its parent.
    if any(
        r.relationship_type == RelationshipType.DESCENDANT_OF
        for r in sbom_doc.relationships
    ):
        LOGGER.debug(
            "[Parent image content] Downloaded parent image "
            "content already contains DESCENDANT_OF relationship."
        )
        return sbom_doc

    sbom_doc = await convert_to_descendant_of_relationship(
        sbom_doc, grandparent_spdx_id
    )
    return sbom_doc


async def adjust_parent_image_spdx_element_ids(
    parent_sbom_doc: Document,
    component_sbom_doc: Document,
    grandparent_spdx_id: str | None,
) -> Document:
    """
    This function modifies downloaded used parent image SBOM. We need to
    distinguish downloaded parent component-only content ("spdxElementId":
    "SPDXRef-image") and current component component-only content (also
    "spdxElementId": "SPDXRef-image"). We achieve this by taking the name
    of the parent from component ("relatedSpdxElement": "parent-name") and
    substitute every "spdxElementId": "SPDXRef-image" in downloaded parent
    content.

    Function initially identifies the name of the parent image in component
    image SBOM.

    Obtained parent image name from component is used to exchange any
    spdxElementId in parent content bearing "spdxElementId": "SPDXRef-image"
    Parent's (contextualized or not) component-only packages
    (packages installed in final layer of the parent) contain
    "spdxElementId": "SPDXRef-image"
    This is allowed only for currently-build-component packages
    (component_sbom_doc).
    This might be extended in the future to cover hermeto-provided
    spdxElementId if differs.

    TODO ISV-5709 OR KONFLUX-3515:
    This function is used for modification of the used parent content
    after resolution and application of the ISV-5709 - we need to have
    diff first OR used for modification during the implementation of
    KONFLUX-3515
    TODO END

    Workflow:
    1. Obtain parent image name as related_spdx_element_id (or SPDXID)
    from component SBOM (this expects component SBOM already with
    DESCENDANT_OF correctly set)
    2. Modify every package's spdx_element_id containing CONTAINS
    and bearing "spdxElementId": "SPDXRef-image" from downloaded
    parent SBOM with value from step 1.
    """
    # Get parent name from already built component
    # SBOM, naturally there will be just one
    descendant_of_spdxids = [
        r.related_spdx_element_id
        for r in component_sbom_doc.relationships
        if r.relationship_type == RelationshipType.DESCENDANT_OF
    ]
    assert len(descendant_of_spdxids) == 1, (
        f"Expecting exactly one DESCENDANT_OF relationship, "
        f"found {len(descendant_of_spdxids)}!"
    )
    parent_name_from_component_sbom = descendant_of_spdxids[0]
    assert isinstance(parent_name_from_component_sbom, str), (
        f"Cannot find parent SPDXID in component SBOM, "
        f"it the image is marked as a descendant of {parent_name_from_component_sbom}!"
    )

    # If parent not contextualized: all packages with
    # CONTAINS relationship are modified
    # If parent already contextualized: only packages that belongs
    # to this parent but not to its grandparent representing
    # component-only content of the parent will be modified
    # (it has already changed spdxElementId, and it is
    # different from SPDXRef-image)
    n_relationships_modified = 0
    parent_self_references = await find_spdx_root_packages_spdxid(parent_sbom_doc)
    assert parent_self_references, "SBOM is missing DESCRIBES relationship!"
    for relationship in parent_sbom_doc.relationships:
        if (
            relationship.relationship_type == RelationshipType.CONTAINS
            and relationship.spdx_element_id in parent_self_references
        ):
            relationship.spdx_element_id = parent_name_from_component_sbom
            n_relationships_modified += 1

        # We also need to modify the DESCENDANT_OF relationship
        # of the parent if grandparent exists saying instead of
        # SPDXRef-image DESCENDANT_OF grandparent_spdx_id but rather
        # parent_name_from_component_sbom DESCENDANT_OF grandparent_spdx_id
        # we do not need to modify the builders of this parent content (BUILD_TOOL_OF),
        # because they will be removed anyway at later stage from this parent content
        if (
            grandparent_spdx_id
            and relationship.relationship_type == RelationshipType.DESCENDANT_OF
            and relationship.related_spdx_element_id == grandparent_spdx_id
        ):
            relationship.spdx_element_id = parent_name_from_component_sbom
            n_relationships_modified += 1

    LOGGER.debug(
        "[%s] Modified %d relationships. "
        "Transformed spdx_element_id: from SPDXRef-image to "
        "%s.",
        ContentType.PARENT.value,
        n_relationships_modified,
        parent_name_from_component_sbom,
    )

    return parent_sbom_doc


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
            "[Parent content] Only the index image of parent was "
            "found for ref %s and arch %s",
            parent_image.reference,
            arch,
        )
    else:
        LOGGER.debug(
            "[Parent content] The specific arch was successfully "
            "located for ref %s and arch %s",
            parent_image.reference,
            arch,
        )

    cosign_client = CosignClient(Path(""))
    try:
        sbom = await cosign_client.fetch_sbom(actual_parent_image)
    except SBOMError:
        LOGGER.info(
            "Contextual mechanism won't be used, there is no parent image SBOM."
        )
        return None
    if not sbom.format.is_spdx2():
        LOGGER.info(
            "Contextual mechanism won't be used, "
            "SBOM format is not supported for this workflow."
        )
        return None
    LOGGER.debug("Contextual mechanism will be used.")
    return sbom.doc


async def remove_parent_image_builder_records(parent_sbom_doc: Document) -> Document:
    """
    Remove BUILD_TOOL_OF packages and relationships from parent image.
    Note: This must only be done after the parent image's
          DESCENDANT_OF relationship has been updated.
    """
    build_tool_ids = []
    new_relationships = []
    for relationship in parent_sbom_doc.relationships:
        if relationship.relationship_type == RelationshipType.BUILD_TOOL_OF:
            build_tool_ids.append(relationship.spdx_element_id)
        else:
            new_relationships.append(relationship)
    LOGGER.debug(
        "Removing BUILD_TOOL_OF relationships and packages for %s", build_tool_ids
    )
    parent_sbom_doc.relationships = new_relationships

    new_packages = [
        p for p in parent_sbom_doc.packages if p.spdx_id not in build_tool_ids
    ]
    parent_sbom_doc.packages = new_packages
    # annotations have to be explicitly removed, or they'll remain in a detached list
    new_annotations = [
        a for a in parent_sbom_doc.annotations if a.spdx_id not in build_tool_ids
    ]
    parent_sbom_doc.annotations = new_annotations

    return parent_sbom_doc


# pylint: disable=unused-argument
async def calculate_component_only_content(
    parent_sbom_doc: Document, component_sbom_doc: Document
) -> Document:
    """
    Function calculates diff between component content
    and parent content and produces component only content.
    """
    raise NotImplementedError("To be implement in ISV-5709")


async def create_contextual_sbom(
    updated_parent_sbom_doc: Document,
    component_only_sbom_doc: Document,
) -> Document:
    """
    Function merges the updated parent image and the component-only image.
    Args:
        updated_parent_sbom_doc: The updated parent image SBOM.
        component_only_sbom_doc: The component-only SBOM.

    Returns:
        The finished contextual SBOM.
    """
    raise NotImplementedError("To be implement in ISV-5714")
