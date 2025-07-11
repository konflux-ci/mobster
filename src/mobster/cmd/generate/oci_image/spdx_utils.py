"""SPDX-2.X utilities for the generate oci-image target"""

import json
from datetime import datetime, timezone
from typing import Any

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster import get_mobster_version
from mobster.image import Image
from mobster.sbom.spdx import get_image_package, get_namespace

BUILDER_IMAGE_PROPERTY = {
    "name": "konflux:container:is_builder_image:additional_builder_image",
    "value": "script-runner-image",
}


async def normalize_actor(actor: str) -> str:
    """
    Adds a necessary actor classificator if not present.
    This allows the SPDX library to load the actor without
    validation issues.
    Defaults to `TOOL`.
    Args:
        actor (str): The input actor.
    Returns:
        str: The normalized actor.
    """
    if not actor.upper().startswith(
        ("TOOL: ", "ORGANIZATION: ", "PERSON: ", "NOASSERTION")
    ):
        return "Tool: " + actor
    return actor


async def normalize_package(package: dict[str, Any]) -> None:
    """
    Adds necessary fields to an SPDX Package to be loaded by the
    SPDX library without validation issues.
    Args:
        package (dict[str, Any]): The package to be normalized.

    Returns:
        None: Nothing, changes are performed in-place.
    """
    if "downloadLocation" not in package:
        package["downloadLocation"] = "NOASSERTION"
    if "name" not in package:
        package["name"] = ""
    if supplier := package.get("supplier"):
        package["supplier"] = await normalize_actor(supplier)


async def normalize_sbom(sbom: dict[str, Any]) -> None:
    """
    Adds necessary fields to an SPDX SBOM to be loaded by the
    SPDX library without validation issues.
    Args:
        sbom (dict[str, Any]): The SBOM to be normalized.

    Returns:
        None: Nothing, changes are performed in-place.
    """
    if "SPDXID" not in sbom:
        sbom["SPDXID"] = "SPDXRef-DOCUMENT"
    if "dataLicense" not in sbom:
        sbom["dataLicense"] = "CC0-1.0"
    if "spdxVersion" not in sbom:
        sbom["spdxVersion"] = "SPDX-2.3"
    if "name" not in sbom:
        sbom["name"] = "MOBSTER:UNFILLED_NAME (please update this field)"
    if "documentNamespace" not in sbom:
        sbom["documentNamespace"] = get_namespace(sbom["name"])

    creation_info = sbom.get("creationInfo", {})
    if "created" not in creation_info:
        creation_info["created"] = "1970-01-01T00:00:00Z"
    creators = creation_info.get("creators", [])
    new_creators = [await normalize_actor(creator) for creator in creators]
    new_creators.append(f"Tool: Mobster-{get_mobster_version()}")
    creation_info["creators"] = new_creators
    sbom["creationInfo"] = creation_info

    for package in sbom.get("packages", []):
        await normalize_package(package)


async def update_sbom_name_and_namespace(sbom: Document, image: Image) -> None:
    """
    Update the SBOM name with the image reference in the format 'repository@digest'.
    Also update its namespace using the same value and Konflux URL.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM
        image (Image): The main image

    Returns:
        None: Nothing, changes are performed in-place.
    """
    name = f"{image.repository}@{image.digest}"
    sbom.creation_info.name = name
    sbom.creation_info.document_namespace = get_namespace(name)


async def find_spdx_root_relationships(sbom: Document) -> list[Relationship]:
    """
    Finds the relationship describing the root element.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM

    Returns:
        spdx_tools.spdx.model.relationship.Relationship: The root relationship
    """
    relationships = []
    for relationship in sbom.relationships:
        for relationship_type in (
            RelationshipType.DESCRIBES,
            RelationshipType.DESCRIBED_BY,
        ):
            # The root element is either DESCRIBED_BY SPDXRef-DOCUMENT
            # or SPDXRef-DOCUMENT DESCRIBES the root element
            if relationship.relationship_type is relationship_type:
                relationships.append(relationship)
    return relationships


async def find_spdx_root_packages_spdxid(sbom_doc: Document) -> list[str]:
    """
    Finds the root element of an SPDX SBOM and returns its SPDXID.
    Args:
        sbom_doc (spdx_tools.spdx.model.document.Document): The SBOM

    Returns:
        list[str]: The SPDXID of the root package
    """
    spdx_ids = set()
    root_relationships = await find_spdx_root_relationships(sbom_doc)
    for root_relationship in root_relationships:
        if (
            root_relationship.relationship_type is RelationshipType.DESCRIBES
            and isinstance(root_relationship.related_spdx_element_id, str)
        ):
            spdx_ids.add(root_relationship.related_spdx_element_id)
        elif isinstance(root_relationship.spdx_element_id, str):
            spdx_ids.add(root_relationship.spdx_element_id)
    return list(spdx_ids)


async def find_spdx_root_packages(sbom: Document) -> list[Package]:
    """
    Finds the root element of an SPDX SBOM and returns its object representation.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM

    Returns:
        list[spdx_tools.spdx.model.package.Package]: The root package
    """
    packages = []
    root_spdxids = set(await find_spdx_root_packages_spdxid(sbom))
    for package in sbom.packages:
        if package.spdx_id in root_spdxids:
            packages.append(package)
    return packages


async def is_virtual_root(package: Package) -> bool:
    """
    Check if the package is a virtual root - usually a package with empty values.

    For example:

        {
            "SPDXID": "SPDXRef-DocumentRoot-Unknown",
            "name": "",
            "versionInfo": ""
        }

        {
            "SPDXID": "SPDXRef-DocumentRoot-Directory-.-some-directory",
            "name": "./some-directory",
            "versionInfo": ""
        }

    Args:
        package (spdx_tools.spdx.model.package.Package):
            A package element from the SBOM.

    Returns:
        bool: A boolean indicating if the package is a virtual root.
    """
    package_name = package.name
    return not package_name or package_name.startswith((".", "/"))


async def redirect_spdx_virtual_root_to_new_root(
    sbom: Document, virtual_root_id: str, new_root_id: str
) -> None:
    """
    Redirect the relationship describing the document to a new root node.
    Args:
        sbom (spdx_tools.spdx.model.document.Document): The SBOM
        virtual_root_id (str): SPDX ID of the virtual root (to be replaced)
        new_root_id (str): SPDX ID of the new root (will replace the old one)

    Returns:
        None: Nothing, changes are performed in-place.
    """
    for relationship in sbom.relationships:
        if relationship.spdx_element_id == virtual_root_id:
            relationship.spdx_element_id = new_root_id

        if relationship.related_spdx_element_id == virtual_root_id:
            relationship.related_spdx_element_id = new_root_id


async def redirect_current_roots_to_new_root(
    sbom: Document, new_root_spdx_id: str
) -> None:
    """
    Redirect all the current root nodes to a new root node.

    Args:
        sbom (dict): SBOM in JSON format.
        new_root_spdx_id (str): New root node identifier.

    Returns:
        dict: Updated SBOM with the new root node identifier.
    """
    current_roots = await find_spdx_root_packages(sbom)
    for current_root in current_roots:
        if await is_virtual_root(current_root):
            # In case the document is described by the virtual root node
            # let's remove it and replace it with the new root node

            # Remove the virtual root node from the packages list
            sbom.packages.remove(current_root)

            # Redirect the existing relationship to the new root node
            await redirect_spdx_virtual_root_to_new_root(
                sbom, current_root.spdx_id, new_root_spdx_id
            )
        else:
            # Make an edge between the new root node and the current root node
            new_relationship = Relationship(
                spdx_element_id=new_root_spdx_id,
                relationship_type=RelationshipType.CONTAINS,
                related_spdx_element_id=current_root.spdx_id,
            )
            sbom.relationships.append(new_relationship)

    # Update the edge between document and the new edge
    for old_root_relationship in await find_spdx_root_relationships(sbom):
        sbom.relationships.remove(old_root_relationship)
    sbom.relationships.append(
        Relationship(
            relationship_type=RelationshipType.DESCRIBES,
            spdx_element_id="SPDXRef-DOCUMENT",
            related_spdx_element_id=new_root_spdx_id,
        )
    )


async def update_package_in_spdx_sbom(
    sbom: Document, image: Image, is_builder_image: bool
) -> Document:
    """
    Update the SPDX SBOM with the image reference.

    The reference to the image is added to the SBOM in the form of a package and
    appropriate relationships are added to the SBOM.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.
        is_builder_image (bool): Is the image used in a builder stage for the component?

    Returns:
        dict: Updated SBOM with the image reference added.
    """
    package = get_image_package(image, image.propose_spdx_id())

    sbom.packages.insert(0, package)
    if is_builder_image:
        # Append the builder image package to the packages list

        annotation = Annotation(
            spdx_id=package.spdx_id,
            annotation_type=AnnotationType.OTHER,
            annotator=Actor(actor_type=ActorType.TOOL, name="konflux:jsonencoded"),
            annotation_comment=json.dumps(
                BUILDER_IMAGE_PROPERTY,
                separators=(",", ":"),
            ),
            annotation_date=datetime.now(timezone.utc),
        )
        sbom.annotations.append(annotation)
        root_spdxids = await find_spdx_root_packages_spdxid(sbom)
        # Add the relationship between the builder image and the package
        for root_spdxid in root_spdxids:
            sbom.relationships.append(
                Relationship(
                    spdx_element_id=package.spdx_id,
                    relationship_type=RelationshipType.BUILD_TOOL_OF,
                    related_spdx_element_id=root_spdxid,
                )
            )
    else:
        # Check existing relationships and redirect the current roots to the new root
        await redirect_current_roots_to_new_root(sbom, package.spdx_id)
    return sbom
