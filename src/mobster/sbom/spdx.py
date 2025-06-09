"""A module for SPDX SBOM format"""

from datetime import datetime, timezone
from uuid import uuid4

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster import get_mobster_version
from mobster.artifact import Artifact
from mobster.image import Image


def get_creation_info(sbom_name: str) -> CreationInfo:
    """
    Create the creation information for the SPDX document.

    Args:
        index_image (Image): An OCI index image object.

    Returns:
        CreationInfo: A creation information object for the SPDX document.
    """
    return CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=sbom_name,
        data_license="CC0-1.0",
        document_namespace=f"https://konflux-ci.dev/spdxdocs/{sbom_name}-{uuid4()}",
        creators=[
            Actor(ActorType.ORGANIZATION, "Red Hat"),
            Actor(ActorType.TOOL, "Konflux CI"),
            Actor(ActorType.TOOL, f"Mobster-{get_mobster_version()}"),
        ],
        created=datetime.now(timezone.utc),
    )


def get_package(image: Image, spdx_id: str, package_name: str | None = None) -> Package:
    """
    Transform the parsed image object into SPDX package object.


    Args:
        image (Image): A parsed image object.
        spdx_id (str): An SPDX ID for the image.

    Returns:
        Package: A package object representing the OCI image.
    """
    if not package_name:
        package_name = image.name if not image.arch else f"{image.name}_{image.arch}"

    package = Package(
        spdx_id=spdx_id,
        name=package_name,
        version=image.tag,
        download_location=SpdxNoAssertion(),
        supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
        license_declared=SpdxNoAssertion(),
        files_analyzed=False,
        external_references=[
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=image.purl_str(),
            )
        ],
        checksums=[
            Checksum(
                algorithm=ChecksumAlgorithm.SHA256,
                value=image.digest_hex_val,
            )
        ],
    )

    return package


def get_package_from_artifact(artifact: Artifact) -> Package:
    """
    Transform the parsed artifact object into SPDX package object.

    Args:
        artifact (Artifact): A parsed artifact object.

    Returns:
        Package: A package object representing the artifact.
    """
    package = Package(
        spdx_id=artifact.propose_spdx_id(),
        name=artifact.filename,
        download_location=artifact.source,
        supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
        license_declared=SpdxNoAssertion(),
        files_analyzed=False,
        external_references=[
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=artifact.purl_str(),
            )
        ],
        checksums=[
            Checksum(
                algorithm=ChecksumAlgorithm.SHA256,
                value=artifact.sha256sum,
            )
        ],
    )

    return package


def get_root_package_relationship(spdx_id: str) -> Relationship:
    """
    Get a relationship for the root package in relation to the SPDX document.
    This relationship indicates that the document describes the root package.

    Args:
        spdx_id (str): An SPDX ID for the root package.

    Returns:
        Relationship: An object representing the relationship for the root package.
    """
    return Relationship(
        spdx_element_id="SPDXRef-DOCUMENT",
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id=spdx_id,
    )
