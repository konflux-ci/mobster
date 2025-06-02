"""A module for CycloneDX SBOM format"""

from typing import Any

from cyclonedx.model import HashType
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import (
    Component,
    ComponentType,
)

from mobster import get_mobster_version
from mobster.artifact import Artifact
from mobster.image import Image


def get_component(image: Image) -> Component:
    """
    Transform the parsed image object into CycloneDX component.


    Args:
        image (Image): A parsed image object.

    Returns:
        Package: A component object representing the OCI image.
    """

    package = Component(
        type=ComponentType.CONTAINER,
        name=image.name if not image.arch else f"{image.name}_{image.arch}",
        version=image.tag,
        purl=image.purl(),
        hashes=[HashType.from_composite_str(image.digest)],
        bom_ref=BomRef(image.propose_cyclonedx_bom_ref()),
    )

    return package


def get_component_from_artifact(artifact: Artifact) -> Component:
    """
    Transform the parsed image object into CycloneDX component.


    Args:
        image (Image): A parsed image object.

    Returns:
        Package: A component object representing the OCI image.
    """

    package = Component(
        type=ComponentType.FILE,
        name=artifact.filename,
        purl=artifact.purl(),
        hashes=[HashType.from_hashlib_alg("sha256", artifact.sha256sum)],
        bom_ref=BomRef(artifact.propose_cyclonedx_bom_ref()),
    )

    return package


def get_tools_component() -> Component:
    """
    Create a metadata.tools CycloneDX component. Inserts current version of
    mobster.

    Returns:
        Component: A metadata.component object.
    """
    return Component(
        name="Mobster", type=ComponentType.APPLICATION, version=get_mobster_version()
    )


def get_tools_component_dict() -> dict[str, Any]:
    """
    Create a metadata.tools CycloneDX component. Inserts current version of
    mobster.

    Returns:
        Component: A metadata.component object.
    """
    component = get_tools_component()
    return {
        "name": component.name,
        "type": component.type.value,
        "version": component.version,
    }
