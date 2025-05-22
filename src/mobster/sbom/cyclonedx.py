"""A module for CycloneDX SBOM format"""

from cyclonedx.model import HashType
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import (
    Component,
    ComponentType,
)

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
