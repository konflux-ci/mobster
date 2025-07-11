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
from spdx_tools.spdx.model.spdx_none import SpdxNone

from mobster import get_mobster_version
from mobster.artifact import Artifact
from mobster.image import Image


def get_root_package_relationship(spdx_id: str) -> Relationship:
    """Get a relationship for the root package in relation to the SPDX document.

    Args:
        spdx_id: An SPDX ID for the root package.

    Returns:
        Relationship: An object representing the relationship for the root package.
    """
    return Relationship(
        spdx_element_id="SPDXRef-DOCUMENT",
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id=spdx_id,
    )


def get_namespace(sbom_name: str) -> str:
    """
    Create a namespace for the SBOM using its name
    and a Konflux URL.
    Args:
        sbom_name (str): Name of the SBOM

    Returns:
        str: The generated documentNamespace
    """
    return f"https://konflux-ci.dev/spdxdocs/{sbom_name}-{uuid4()}"


def get_creation_info(sbom_name: str) -> CreationInfo:
    """Create the creation information for the SPDX document.

    Args:
        sbom_name: The name for the SBOM document.

    Returns:
        CreationInfo: A creation information object for the SPDX document.
    """
    return CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=sbom_name,
        data_license="CC0-1.0",
        document_namespace=get_namespace(sbom_name),
        creators=[
            Actor(ActorType.ORGANIZATION, "Red Hat"),
            Actor(ActorType.TOOL, "Konflux CI"),
            Actor(ActorType.TOOL, f"Mobster-{get_mobster_version()}"),
        ],
        created=datetime.now(timezone.utc),
    )


def get_image_package(
    image: Image, spdx_id: str, package_name: str | None = None
) -> Package:
    """Transform the parsed image object into SPDX package object.

    Args:
        image: A parsed image object.
        spdx_id: An SPDX ID for the image.
        package_name: An optional package name. The image name and architecture
            will be used if not provided.

    Returns:
        Package: A package object representing the OCI image.
    """
    if not package_name:
        package_name = image.name if not image.arch else f"{image.name}_{image.arch}"

    return get_package(
        spdx_id,
        name=package_name,
        version=image.tag,
        external_refs=[
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


def get_package_from_artifact(artifact: Artifact) -> Package:
    """Transform the parsed artifact object into SPDX package object.

    Args:
        artifact: A parsed artifact object.

    Returns:
        Package: A package object representing the artifact.
    """
    return get_package(
        spdx_id=artifact.propose_spdx_id(),
        name=artifact.filename,
        download_location=artifact.source,
        external_refs=[
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


# pylint: disable=too-many-arguments,too-many-positional-arguments
def get_package(
    spdx_id: str,
    name: str,
    external_refs: list[ExternalPackageRef],
    checksums: list[Checksum],
    version: str | None = None,
    download_location: str | SpdxNoAssertion | SpdxNone | None = None,
) -> Package:
    """Create an SPDX package from input data.

    Args:
        spdx_id: An SPDX ID of the package.
        name: Name field of the package.
        external_refs: List of SPDX external references.
        checksums: List of SPDX checksums.
        version: Version field of the package.
        download_location: Package download location. If not provided,
            SpdxNoAssertion is used.

    Returns:
        Package: An SPDX package object.
    """
    if download_location is None:
        download_location = SpdxNoAssertion()

    return Package(
        spdx_id=spdx_id,
        name=name,
        version=version,
        download_location=download_location,
        supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
        license_declared=SpdxNoAssertion(),
        files_analyzed=False,
        external_references=external_refs,
        checksums=checksums,
    )
