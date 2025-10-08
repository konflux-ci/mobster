"""
Module accessing used parent image content in SBOMs and
modifying component content to indicate relationships with parent.
"""

import json
import logging
from typing import Any, Literal

from packageurl import PackageURL
from spdx_tools.spdx.model.actor import ActorType
from spdx_tools.spdx.model.annotation import Annotation
from spdx_tools.spdx.model.checksum import Checksum
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import ExternalPackageRefCategory, Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.constants import (
    HERMETO_ANNOTATION_COMMENTS,
    IS_BASE_IMAGE_ANNOTATION,
)
from mobster.cmd.generate.oci_image.spdx_utils import (
    find_spdx_root_packages_spdxid,
    get_annotations_by_spdx_id,
    get_package_by_spdx_id,
)
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.cosign import CosignClient, CosignConfig

LOGGER = logging.getLogger(__name__)


def get_grandparent_annotation(parent_sbom_doc: Document) -> Annotation | None:
    """
    Searches used parent image annotation in the used parent
    image content according to the annotation comment

    Args:
        parent_sbom_doc (Document): The used parent image sbom.

    Returns:
        Annotation spdx_id: The used parent image annotation spdx_id or None.
    """
    for annotation in parent_sbom_doc.annotations:
        try:
            if json.loads(annotation.annotation_comment) == IS_BASE_IMAGE_ANNOTATION:
                return annotation
        except json.JSONDecodeError:
            LOGGER.debug(
                "Annotation comment '%s' is not in JSON format.",
                annotation.annotation_comment,
            )

    LOGGER.debug(
        "[Parent image content] Cannot determine parent of the "
        "downloaded parent image SBOM. It either does "
        "not exist (it was an oci-archive or the image is built from "
        "scratch), it is malformed or the downloaded SBOM"
        "is not sourced from konflux."
    )
    return None


def get_relationship_by_spdx_id(
    doc: Document,
    spdx_id: str,
    expected_relationship_type: Literal[RelationshipType.DESCENDANT_OF]
    | Literal[RelationshipType.BUILD_TOOL_OF] = RelationshipType.BUILD_TOOL_OF,
) -> Relationship | None:
    """
    Gets DESCENDANT_OF or BUILD_TOOL_OF relationship by spdx id from SPDX document.

    Args:
        doc (Document): The SPDX SBOM document.
        spdx_id (str): The SPDX SBOM ID.
        expected_relationship_type (RelationshipType): The expected relationship type.

    Returns:
        Relationship | None: The relationship or None.
    """
    if expected_relationship_type is RelationshipType.BUILD_TOOL_OF:
        return next(
            (
                r
                for r in doc.relationships
                if r.spdx_element_id == spdx_id
                and r.relationship_type == expected_relationship_type
            ),
            None,
        )

    return next(
        (
            r
            for r in doc.relationships
            if r.related_spdx_element_id == spdx_id
            and r.relationship_type == expected_relationship_type
        ),
        None,
    )


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

    cosign_client = CosignClient(CosignConfig())
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
    and bears only single DESCENDANT_OF relationship pointing to its parent.
    Later, when mapping mechanism will map packages from downloaded parent
    to this component content, matched packages (all matched when parent is
    non-contextualized, otherwise only parent-only packages) will
    adopt this SPDXID binding them to the used parent image instead
    of this component.

    Args:
        component_sbom_doc: Non-contextualized component SBOM with
            DESCENDANT_OF relationship pointing to used parent image.

    Returns:
        SPDX ID of the parent image defined by this component.
        It is always present.

    Raises:
        SBOMError: If the passed SBOM does not contain DESCENDANT_OF relationship.
            This should never happen unless regression happen in mobster in
            functionality adding this relationship to component content.
    """
    for relationship in component_sbom_doc.relationships:
        if relationship.relationship_type == RelationshipType.DESCENDANT_OF:
            return relationship.related_spdx_element_id

    raise SBOMError(
        "Passed component SBOM does not contain any DESCENDANT_OF "
        "relationship. Parent name cannot be determined."
    )


def process_build_tool_of_grandparent_item(
    grandparent_package: Package,
    grandparent_annotation: Annotation,
    grandparent_relationship: Relationship,
    parent_spdx_id_from_component: str,
) -> list[tuple[Package, Relationship, Annotation]]:
    """
    Absence of the DESCENDANT_OF relationships in downloaded
    used parent image SBOM indicates that SBOM was produced
    in pre-mobster era and parent of this image has been
    indicated as `grandparent BUILD_TOOL_OF parent`.

    Before transferring this relationship to component we
    need to convert it to `parent DESCENDANT_OF grandparent`

    Parent name from component must be used to align CONTAINS
    relationships in final component SBOM.

    Args:
        grandparent_package: Grandparent package
        grandparent_annotation: Grandparent annotation
        grandparent_relationship: Grandparent relationship
        parent_spdx_id_from_component: SPDX ID of parent
            image from component SBOM

    Returns:
        List with single BUILD_TOOL_OF relationship converted to DESCENDANT_OF
        indicating parent of the component parent (component's grandparent)
    """
    grandparent_package.files_analyzed = False

    parent_grandparent_relationship = Relationship(
        spdx_element_id=parent_spdx_id_from_component,
        related_spdx_element_id=grandparent_relationship.spdx_element_id,
        relationship_type=RelationshipType.DESCENDANT_OF,
    )

    return [
        (grandparent_package, parent_grandparent_relationship, grandparent_annotation)
    ]


def process_descendant_of_grandparent_items(
    parent_sbom_doc: Document,
    grandparent_package: Package | None,
    parent_spdx_id_from_component: str,
    descendant_of_packages_relationships: list[tuple[Package, Relationship]],
) -> list[tuple[Package, Relationship, Any]]:
    """
    Downloaded used parent image SBOM is contextualized (contains more
    DESCENDANT_OF relationships - `parent DESCENDANT_OF grandparent`,
    `grandparent DESCENDANT_OF ...`) OR produced by mobster with
    contextualization disabled (contains only single DESCENDANT_OF
    relationship - `parent DESCENDANT_OF grandparent`)

    All DESCENDANT_OF relationships and packages are associated
    with the annotations before copied to component.

    Also, `parent DESCENDANT_OF grandparent` relationship must
    be renamed to `parent_name_from_component DESCENDANT_OF grandparent`
    to align CONTAINS relationships in final component SBOM.

    Args:
        parent_sbom_doc: used parent SBOM that was contextualized or
            produced by mobster.
        grandparent_package: Grandparent package.
        parent_spdx_id_from_component: SPDX ID of parent from component.
        descendant_of_packages_relationships: list of tuples containing
            associated packages and DESCENDANT_OF relationships.

    Returns:
        Associated DESCENDANT_OF relationships with packages
        and associated annotations.
    """
    descendant_of_items: list[tuple[Package, Relationship, Annotation | None]] = []
    for pkg, rel in descendant_of_packages_relationships:
        # Substitution of the parent name to parent name from component
        if grandparent_package and grandparent_package.spdx_id == pkg.spdx_id:
            rel = Relationship(
                spdx_element_id=parent_spdx_id_from_component,
                related_spdx_element_id=rel.related_spdx_element_id,
                relationship_type=rel.relationship_type,
            )

        annotation = None
        for annot in parent_sbom_doc.annotations:
            if pkg.spdx_id == annot.spdx_id:
                annotation = annot
        if not annotation:
            LOGGER.warning("Annotation not found for %s", pkg.spdx_id)
        descendant_of_items.append((pkg, rel, annotation))

    return descendant_of_items


def get_descendant_of_items_from_used_parent(
    parent_sbom_doc: Document, parent_spdx_id_from_component: str
) -> list[tuple[Package, Relationship, Annotation]]:
    """
    Obtains all of used parent image DESCENDANT_OF relationships, related
    packages, and their annotations and groups them together.
    DESCENDANT_OF relationships packages and their annotations
    will be supplemented into final component SBOM after
    contextualization to establish relationships with
    grandparents of the component.

    If no DESCENDANT_OF relationship was found, used parent image had to be
    produced by legacy workflow, where such relationship was expressed as
    `grandparent BUILD_TOOL_OF parent` - we need to convert it to
    DESCENDANT_OF relationship and rename `parent` as it is named in
    component before we pass this relationship to component.

    Args:
        parent_sbom_doc: Downloaded used parent image SBOM.
        parent_spdx_id_from_component: Name of the used parent from
            component SBOM

    Returns:
        List of DESCENDANT_OF relationships, their packages and annotations
        from used parent SBOM.
    """
    grandparent_annotation = get_grandparent_annotation(parent_sbom_doc)

    # Grandparent of the downloaded used parent image SBOM cannot
    # be determined. SBOM is either malformed, not sourced from
    # konflux, or built from scratch or as an oci-archive. There
    # are no DESCENDANT_OF relationships to add into component.
    if not grandparent_annotation:
        return []

    grandparent_package = get_package_by_spdx_id(
        parent_sbom_doc, grandparent_annotation.spdx_id
    )
    # package must be present as well
    if not grandparent_package:
        LOGGER.warning(
            "No package found for annotation %s in downloaded parent SBOM %s",
            grandparent_annotation.spdx_id,
            parent_sbom_doc.creation_info.name,
        )
        return []

    packages_with_related_descendant_of_relationships = (
        associate_relationships_and_related_packages(
            parent_sbom_doc.packages,
            parent_sbom_doc.relationships,
            relationship_type=RelationshipType.DESCENDANT_OF,
        )
    )

    if not packages_with_related_descendant_of_relationships:
        grandparent_relationship = get_relationship_by_spdx_id(
            parent_sbom_doc,
            grandparent_annotation.spdx_id,
            expected_relationship_type=RelationshipType.BUILD_TOOL_OF,
        )
        # Defensive approach: when grandparent package exists,
        # relationship must be present as well
        if not grandparent_relationship:
            LOGGER.warning(
                "No BUILD_TOOL_OF relationship found for "
                "package %s in downloaded parent SBOM %s",
                grandparent_package.spdx_id,
                parent_sbom_doc.creation_info.name,
            )
            return []

        return process_build_tool_of_grandparent_item(
            grandparent_package,
            grandparent_annotation,
            grandparent_relationship,
            parent_spdx_id_from_component,
        )

    return process_descendant_of_grandparent_items(
        parent_sbom_doc,
        grandparent_package,
        parent_spdx_id_from_component,
        packages_with_related_descendant_of_relationships,
    )


def associate_relationships_and_related_packages(
    packages: list[Package],
    relationships: list[Relationship],
    relationship_type: RelationshipType,
) -> list[tuple[Package, Relationship]]:
    """
    Associate relationships (related_spdx_element_id) and related
    packages (spdx_id) together for given relationship type.
    Args:
        packages: List of Package objects.
        relationships: List of Relationship objects.
        relationship_type: Relationship type.

    Returns:
        List of tuples of related package and relationship objects.
    """
    assoc_package_relationship = []

    for pkg in packages:
        for rel in relationships:
            if (
                pkg.spdx_id == rel.related_spdx_element_id
                and rel.relationship_type == relationship_type
            ):
                assoc_package_relationship.append((pkg, rel))
                break

    return assoc_package_relationship


async def map_parent_to_component_and_modify_component(
    parent_sbom_doc: Document,
    component_sbom_doc: Document,
    parent_spdx_id_from_component: str,
    descendant_of_items_from_used_parent: list[
        tuple[Package, Relationship, Annotation]
    ],
) -> Document:
    """
    Function maps packages from downloaded used parent to the
    component content, and modifies relationships in component,
    when package is sourced from parent (or grandparents)
    Args:
        parent_sbom_doc: Downloaded used parent image SBOM
            (can be contextualized or not).
        component_sbom_doc: The component SBOM to be contextualized.
        parent_spdx_id_from_component: The name of the used parent that is
            determined at component SBOM generation.
        descendant_of_items_from_used_parent: DESCENDANT_OF relationships,
            related packages and relationships from used parent SBOM -
            grandparents of the component.

    Returns:
        Fully contextualized component SBOM.
    """
    parent_root_packages = await find_spdx_root_packages_spdxid(parent_sbom_doc)

    parent_package_with_contains_relationship = (
        associate_relationships_and_related_packages(
            parent_sbom_doc.packages,
            parent_sbom_doc.relationships,
            relationship_type=RelationshipType.CONTAINS,
        )
    )
    component_package_with_contains_relationship = (
        associate_relationships_and_related_packages(
            component_sbom_doc.packages,
            component_sbom_doc.relationships,
            relationship_type=RelationshipType.CONTAINS,
        )
    )

    for (
        parent_package,
        parent_relationship,
    ) in parent_package_with_contains_relationship:
        for (
            component_package,
            component_relationship,
        ) in component_package_with_contains_relationship:
            if package_matched(parent_sbom_doc, parent_package, component_package):
                _modify_relationship_in_component(
                    component_relationship,
                    parent_relationship,
                    parent_spdx_id_from_component,
                    parent_root_packages,
                )

    _supply_ancestors_from_parent_to_component(
        component_sbom_doc,
        descendant_of_items_from_used_parent,
    )
    return component_sbom_doc


def _supply_ancestors_from_parent_to_component(
    component_sbom_doc: Document,
    descendant_of_items_from_used_parent: list[
        tuple[Package, Relationship, Annotation]
    ],
) -> Document:
    """
    Function supply all DESCENDANT_OF relationships
    (and related packages and annotations) from downloaded
    used parent content to component SBOM. Expects that all
    relationships of component's packages already point to
    this packages in _modify_relationship_in_component function.

    Supplied ancestors are grandparents of the component (parent
    package annotation and relationship are already there) and
    annotation comment must be modified for proper functioning
    of the contextual workflow in situation
    when this component will be used as base image for another
    component, and get_grandparent_annotation will


    Args:
        component_sbom_doc: The full generated component SBOM.
        descendant_of_items_from_used_parent: All DESCENDANT_OF
            relationships, associated packages
            and their annotations

    Returns:
        Component SBOM that is fully contextualized.
    """
    for pkg, rel, annot in descendant_of_items_from_used_parent:
        component_sbom_doc.relationships.append(rel)
        component_sbom_doc.packages.append(pkg)
        if annot:
            if annot.annotation_comment:
                annot.annotation_comment = annot.annotation_comment.replace(
                    "is_base_image", "is_ancestor_image"
                )
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
            A) If parent has been contextualized there are two options of the
            component's relationship modification after packages match,
            depending on the information in used parent SBOM:
            1. component CONTAINS package -> grandparent CONTAINS package
            2. component CONTAINS package ->
            parent (parent_spdx_id_from_component) CONTAINS package
            B) If downloaded used parent is not contextualized there is only
            one option for the component's relationship modification:
            component CONTAINS package ->
            1. parent (parent_spdx_id_from_component) CONTAINS package

        parent_spdx_id_from_component: The name of the used parent that
            is determined at component SBOM generation.

        parent_root_packages: This decides if CONTAINS relationship is copied
            (grandparent) or modified (every package in non-contextualized parent
            OR every other package in contextualized parent that is not bound to
            its parent (component's grandparent)).


    Returns: None. Component SBOM is modified in-place.
    """
    # Contextualized parent: matched package is bound to parent itself
    # (not to any of the grandparents),
    # and when we want to point relationship from component to parent
    # we need to use parent name from generated component
    # Non-contextualized parent: all the packages are bound to the
    # parent, we need to use parent name from generated component
    if parent_relationship.spdx_element_id in parent_root_packages:
        component_relationship.spdx_element_id = parent_spdx_id_from_component

    # Contextualized parent: matched package is not bound to the root package(s) but
    # bound to some grandparent of the parent by previous contextualization - we
    # need to preserve this relationship
    # Non-contextualized parent or parent without another parent (no grandparent for
    # component): should never reach this branch, because all
    # the packages will always be bound to parent itself - all relationships will
    # refer to root packages, no grandparents are present by contextualization or
    # in reality
    else:
        component_relationship.spdx_element_id = parent_relationship.spdx_element_id


def generated_by_hermeto(annotations: list[Annotation]) -> bool:
    """
    Will determine if the package was generated by hermeto/cachi2 based on its
    annotation.

    Args:
        annotations: list of annotations of the package.

    Returns:
        True if the annotation indicates that the package was generated by
        hermeto/cachi2, False otherwise.
    """
    if not annotations:
        return False

    return any(
        annot.annotator.actor_type == ActorType.TOOL
        and annot.annotation_comment in HERMETO_ANNOTATION_COMMENTS
        for annot in annotations
    )


def get_package_purl(package: Package) -> str | None:
    """
    The purl of a package (external reference of category PACKAGE-MANAGER and purl type)

    Args:
        package: The package to find the purl of.

    Returns:
        The purl of the given package or None.
    """
    for ref in package.external_references:
        if (
            ref.category == ExternalPackageRefCategory.PACKAGE_MANAGER
            and ref.reference_type == "purl"
        ):
            return ref.locator
    return None


def validate_and_compare_purls(
    parent_purl: str | None,
    component_purl: str | None,
) -> bool:
    """
    Validate that the purls contains the required fields (type, name and version). Then
    compare the compare purls based on the required fields and the namespace.

    Args:
        parent_purl: The parent purl to validate and compare with the component purl.
        component_purl: The component purl to validate and compare with the parent purl.

    Returns:
        True if the purls match after validation, False if either purl is invalid, or
        the validated purls don't match.
    """
    # ValueError is thrown if a purl is None, or missing type or name.
    try:
        parent_purl_obj = PackageURL.from_string(parent_purl)  # type: ignore[arg-type]
        component_purl_obj = PackageURL.from_string(component_purl)  # type: ignore[arg-type]
    except ValueError:
        return False

    if not parent_purl_obj.version or not component_purl_obj.version:
        return False

    return (
        parent_purl_obj.type == component_purl_obj.type
        and parent_purl_obj.name == component_purl_obj.name
        and parent_purl_obj.version == component_purl_obj.version
        and parent_purl_obj.namespace == component_purl_obj.namespace
    )


def checksums_match(
    parent_checksums: list[Checksum], component_checksums: list[Checksum]
) -> bool:
    """
    Compare two lists of Package Checksum objects. All checksums must match.

    Args:
        parent_checksums: List of Checksum objects from parent package.
        component_checksums: List of Checksum objects from component package.

    Returns:
        True if any ofthe checksums match, False otherwise.
    """
    # The Checksum objects are not hashable and do not have to_string(), convert them to
    # strings in a custom way
    parent_checksums_str = [
        str(checksum.algorithm) + ":" + checksum.value for checksum in parent_checksums
    ]
    component_checksums_str = [
        str(checksum.algorithm) + ":" + checksum.value
        for checksum in component_checksums
    ]
    return set(parent_checksums_str) == set(component_checksums_str)


def package_matched(
    parent_sbom_doc: Document,
    parent_package: Package,
    component_package: Package,
) -> bool:
    """
    Determine if a component package matches a parent package for SBOM
    contextualization. The matching strategy depends on the tool that generated the
    packages:

    **Hermeto-to-Syft matching:**
    - Parent packages generated by Hermeto are compared to component packages generated
      by Syft.
    - Matching is done by comparing validated purls (type, name, version, and optionally
      namespace). If either purl fails validation, the packages are considered not
      matched.

    **Syft-to-Syft matching:**
    - Both parent and component packages are generated by Syft.
    - Uses prioritized matching with identifiers checked from most to least specific:
      1. Package checksums (all items in the lists must match)
      2. Package verification codes
      3. Validated purls (type, name, version, and optionally namespace). If either purl
         fails validation, the packages are considered not matched.

    There is no Hermeto-to-Hermeto matching because Hermeto produces component-only
    content that was added during build. Therefore a Hermeto-generated component package
    should never be matched with any parent content. On the other hand, Syft scans the
    entire image including parent content, so Syft-generated components can potentially
    be matched with parent packages generated by either tool.

    Args:
        parent_sbom_doc: The parent SBOM document.
        parent_package: The parent package.
        component_package: The component package.

    Returns:
        True if the packages match based on the criteria above, False otherwise.
    """
    parent_package_annotations = get_annotations_by_spdx_id(
        parent_sbom_doc, parent_package.spdx_id
    )

    parent_purl = get_package_purl(parent_package)
    component_purl = get_package_purl(component_package)

    # Hermeto-to-syft matching
    if generated_by_hermeto(parent_package_annotations):
        return validate_and_compare_purls(parent_purl, component_purl)

    # Syft-to-syft matching: Check identifiers from most specific to least specific
    if parent_package.checksums or component_package.checksums:
        return checksums_match(parent_package.checksums, component_package.checksums)

    if parent_package.verification_code or component_package.verification_code:
        return parent_package.verification_code == component_package.verification_code

    return validate_and_compare_purls(parent_purl, component_purl)
