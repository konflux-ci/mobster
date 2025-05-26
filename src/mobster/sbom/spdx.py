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
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster import get_mobster_version
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


def get_package(image: Image, spdx_id: str) -> Package:
    """
    Transform the parsed image object into SPDX package object.


    Args:
        image (Image): A parsed image object.
        spdx_id (str): An SPDX ID for the image.

    Returns:
        Package: A package object representing the OCI image.
    """

    package = Package(
        spdx_id=spdx_id,
        name=image.name if not image.arch else f"{image.name}_{image.arch}",
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
