"""Module accessing and modifying parent image content in SBOMs."""

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.constants import (
    IS_BASE_IMAGE_ANNOTATION,
)
from mobster.cmd.generate.oci_image.spdx_utils import find_spdx_root_packages_spdxid
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.cosign import CosignClient

LOGGER = logging.getLogger(__name__)


def get_used_parent_image_from_legacy_sbom(
    data: Document,
) -> tuple[Package | None, Annotation, Relationship | None] | tuple[None, None, None]:
    """
    Identifies used parent image in the legacy component content.
    Counts on marking in the downloaded parent image SBOM.

    Args:
        data: SPDX Document object containing the annotations.
    Returns:
        package and annotation of the used parent image.
    """
    for annotation in data.annotations:
        try:
            if json.loads(annotation.annotation_comment) == IS_BASE_IMAGE_ANNOTATION:
                annotation_spdx_id = annotation.spdx_id

                pkg = next(
                    (p for p in data.packages if p.spdx_id == annotation_spdx_id), None
                )
                rel = next(
                    (
                        r
                        for r in data.relationships
                        if r.spdx_element_id == annotation_spdx_id
                    ),
                    None,
                )
                return pkg, annotation, rel
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
    return None, None, None


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


def get_parent_spdx_id_from_component(component_sbom_doc: Document) -> Any:
    """
    Obtains the component's used parent image SPDXID from DESCENDANT_OF
    relationship. Component SBOM is created before contextualization
    and bears only single DESCENDANT_OF relationship.
    Later, when mapping mechanism will map packages from downloaded parent
    to this component content, matched packages (all when parent is
    non-contextualized, otherwise only parent-only packages) will
    adopt this SPDXID bounding them ot the used parent image instead
    of this component.

    Args:
        component_sbom_doc: Non-contextualized component SBOM.

    Returns:
        SPDX ID of the parent image defined by this component.
        It is always present.

    Raises:
        SBOMError: If the passed SBOM does not contain DESCENDANT_OF relationship.
        This should never happen unless regression in mobster in functionality
        adding this relationship to component content.
    """
    for relationship in component_sbom_doc.relationships:
        if relationship.relationship_type == RelationshipType.DESCENDANT_OF:
            return relationship.related_spdx_element_id

    raise SBOMError(
        "Passed component SBOM does not contain any DESCENDANT_OF "
        "relationship. Parent name cannot be determined."
    )


def get_descendant_of_relationships_packages_from_used_parent(
    parent_image_sbom: Document, parent_spdx_id_from_component: str
) -> list[Any]:
    """
    Obtains all of used parent image DESCENDANT_OF packages, their
    relationships, and annotations and groups them together
    DESCENDANT_OF packages, annotations and their relationships
    will be supplemented into final component SBOM after
    contextualization to establish relationships with parent's grandparent.

    If no DESCENDANT_OF relationship was found, the parent image has been
    produced by legacy workflow, where is such relationship indicating used
    parent image expressed as grandparent BUILD_TOOL_OF parent - we need to
    convert it to DESCENDANT_OF relationship rename `parent` as it is named in
    component before we pass it to component.

    Args:
        parent_image_sbom: Downloaded used parent image SBOM.
        parent_spdx_id_from_component:

    Returns:
        List of DESCENDANT_OF relationships, their packages and annotations.
    """
    descendant_of_packages_relationships = normalize_and_filter(
        parent_image_sbom.packages,
        parent_image_sbom.relationships,
        predicate=_package_with_descendant_of_relationship,
    )
    # [Downloaded used parent image SBOM is not contextualized] absence of the
    # DESCENDANT_OF relationships indicates that SBOM was
    # produced in pre-mobster era and used parent image has been indicated as
    # `grandparent BUILD_TOOL_OF parent`. We need to transfer this relationship
    # to component and convert it to `parent DESCENDANT_OF grandparent`
    descendant_of_packages_relationships_annotations = []
    used_parent_image_package, annotation, relationship = (
        get_used_parent_image_from_legacy_sbom(parent_image_sbom)
    )
    if not descendant_of_packages_relationships:
        # parent was build from scratch or it is an oci-archive
        if not used_parent_image_package or not relationship:
            return []
        used_parent_image_package.files_analyzed = False
        relationship.relationship_type = RelationshipType.DESCENDANT_OF
        # Substitution of the parent name from
        # parent to name of the parent from component
        grandparent_name = relationship.spdx_element_id
        relationship.spdx_element_id = parent_spdx_id_from_component
        relationship.related_spdx_element_id = grandparent_name
        extended_assoc = (used_parent_image_package, relationship, annotation)
        descendant_of_packages_relationships_annotations.append(extended_assoc)
        return descendant_of_packages_relationships_annotations

    # [Downloaded used parent image SBOM is contextualized]
    # All DESCENDANT_OF relationships must be copied to component. Last one saying
    # `parent DESCANDANT_OF grandparent` must be renamed to
    # `parent_name_from_component DESCANDANT_OF grandparent`
    # to be meaningful in component SBOM.
    for pkg, rel in descendant_of_packages_relationships:
        annotation_found = False
        for annot in parent_image_sbom.annotations:
            # Substitution of the parent name from
            # parent to name of the parent from component
            if (
                used_parent_image_package
                and used_parent_image_package.spdx_id == pkg.spdx_id
            ):
                rel.spdx_element_id = parent_spdx_id_from_component
            if pkg.spdx_id == annot.spdx_id:
                annotation_found = True
                extended_assoc = (pkg, rel, annot)
                descendant_of_packages_relationships_annotations.append(extended_assoc)
        # Defensive approach: all DESCENDANT_OF packages should have
        # annotations attached and thus this should be never reached
        if not annotation_found:
            extended_assoc = (pkg, rel, None)
            descendant_of_packages_relationships_annotations.append(extended_assoc)

    return descendant_of_packages_relationships_annotations


def _package_with_contains_relationship(pkg: Package, rel: Relationship) -> bool:
    """Maps package with its CONTAINS relationship"""
    return (
        pkg.spdx_id == rel.related_spdx_element_id
        and rel.relationship_type == RelationshipType.CONTAINS
    )


def _package_with_descendant_of_relationship(pkg: Package, rel: Relationship) -> bool:
    """Maps package with its DESCENDANT_OF relationship"""
    return (
        pkg.spdx_id == rel.related_spdx_element_id
        and rel.relationship_type == RelationshipType.DESCENDANT_OF
    )


def normalize_and_filter(
    packages: list[Package],
    relationships: list[Relationship],
    predicate: Callable[[Package, Relationship], bool],
) -> list[tuple[Package, Relationship]]:
    """
    Associate packages and relationships together according
    to the condition specified by passed predicate function
    Args:
        packages: List of Package objects.
        relationships: List of Relationship objects.
        predicate: Predicate function with specific condition

    Returns:
        List of tuples of related package and relationship objects.
    """
    assoc_package_relationship = []

    for pkg in packages:
        for rel in relationships:
            if predicate(pkg, rel):
                assoc = (pkg, rel)
                assoc_package_relationship.append(assoc)
                break

    return assoc_package_relationship


async def map_parent_to_component_and_modify_component(
    parent_image_sbom: Document,
    component_sbom_doc: Document,
    parent_spdx_id_from_component: str,
    descendant_of_rels_pkgs_annots_from_used_parent: list[
        tuple[Package, Relationship, Annotation]
    ],
) -> Document:
    """
    Function maps packages from downloaded used parent to the
    component content, and modifies relationships in component,
    when package is sourced from parent
    Args:
        parent_image_sbom: Downloaded used parent image SBOM
        (can be contextualized or not).
        component_sbom_doc: The full generated component SBOM to be contextualized.
        parent_spdx_id_from_component: The name of the used parent that is
        determined at component SBOM generation.
        descendant_of_rels_pkgs_annots_from_used_parent: When downloaded used parent
        image SBOM is contextualized, those are its DESCENDANT_OF relationships and
        related packages and relationships

    Returns:
        None. Component SBOM is in-place modified and packages that
        were matched between parent and component are now pointing to
        parent and eventually grandparents.
    """
    parent_root_packages = await find_spdx_root_packages_spdxid(parent_image_sbom)

    parent_package_with_relationship = normalize_and_filter(
        parent_image_sbom.packages,
        parent_image_sbom.relationships,
        predicate=_package_with_contains_relationship,
    )
    component_package_with_relationship = normalize_and_filter(
        component_sbom_doc.packages,
        component_sbom_doc.relationships,
        predicate=_package_with_contains_relationship,
    )

    for parent_package, parent_relationship in parent_package_with_relationship:
        for (
            component_package,
            component_relationship,
        ) in component_package_with_relationship:
            if package_matched(parent_package, component_package):
                _modify_relationship_in_component(
                    component_relationship,
                    parent_relationship,
                    parent_spdx_id_from_component,
                    parent_root_packages,
                )

    _supply_descendants_from_parent_to_component(
        component_sbom_doc,
        descendant_of_rels_pkgs_annots_from_used_parent,
    )
    return component_sbom_doc


def _supply_descendants_from_parent_to_component(
    component_sbom_doc: Document,
    descendant_of_rels_pkgs_annots_from_used_parent: list[
        tuple[Package, Relationship, Annotation]
    ],
) -> Document:
    """
    Function supply all DESCENDANT_OF relationships
    (and related packages and annotations) from downloaded
    used parent content to component SBOM. Expects that all
    relationships of component's packages already point to
    this packages in _modify_relationship_in_component function.

    Args:
        component_sbom_doc: The full generated component SBOM.
        descendant_of_rels_pkgs_annots_from_used_parent: All
        DESCENDANT_OF relationships, associated packages and
        their annotations

    Returns:
        None. Component SBOM is fully contextualized.
    """
    for pkg, rel, annot in descendant_of_rels_pkgs_annots_from_used_parent:
        component_sbom_doc.relationships.append(rel)
        component_sbom_doc.packages.append(pkg)
        if annot:
            component_sbom_doc.annotations.append(annot)

    return component_sbom_doc


def _modify_relationship_in_component(
    component_relationship: Relationship,
    parent_relationship: Relationship,
    parent_spdx_id_from_component: str,
    parent_root_packages: list[str],
) -> None:
    """
    Function modifies relationship in component SBOM.
    If package from parent image content was found in
    component content by package_matched function,
    relationship of the package in component content
    is swapped to parent or grandparents
    (if parent is contextualized)

    Args:
        component_relationship: Component relationship to-be-modified.

        parent_relationship: Parent relationship.
        A) If parent has been contextualized and this relationship point
        on its parent(component's grandparent) relationship, it has to be
        transferred to component.
        component CONTAINS package -> grandparent CONTAINS package
        B) If downloaded used parent is not contextualized OR it is
        but relationship indicates that the content has been installed in
        this parent relationship must indicate used parent content
        (parent_spdx_id_from_component)
        component CONTAINS package ->
        parent (parent_spdx_id_from_component) CONTAINS package

        parent_spdx_id_from_component: The name of the used parent that
        is determined at component SBOM generation.

        parent_root_packages: If spdx_element_id of the parent relationship is
        a root package (DESCRIBES) then in component this package must point on
        this parent (B) variant)
        If it is not, the relationship in parent points to the grandparent of
        the component, and this relationship must be transferred to the component
    """
    # Contextualized parent: matched package is bounded to parent itself,
    # and when we want to point relationship from component to parent
    # we need to use parent name from generated component
    # Non-contextualized parent: all the packages are bounded to the
    # parent, we need to use parent name from generated component
    if parent_relationship.spdx_element_id in parent_root_packages:
        component_relationship.spdx_element_id = parent_spdx_id_from_component

    # Contextualized parent: matched package is not bounded to the root package(s) but
    # bounded to some grandparent of the parent by previous contextualization - we
    # need to preserve this relationship
    # Non-contextualized parent: should never reach this branch, because all
    # the packages will always be bounded to parent itself - all relationships will
    # refer to root packages
    else:
        component_relationship.spdx_element_id = parent_relationship.spdx_element_id


def package_matched(parent_package: Package, component_package: Package) -> bool:
    """
    TODO: Full functionality implemented in ISV-5709

    Args:
        parent_package: The parent package.
        component_package: The component package.

    Returns:
        True if the package matched False otherwise.
    """
    return parent_package.spdx_id == component_package.spdx_id
