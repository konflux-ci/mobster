"""
Module for adding an image reference to SBOM (root SBOM element or a builder image)
"""

from cyclonedx.model import Property
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.model.document import (
    Document,
)

from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.generate.oci_image.spdx_utils import (
    BUILDER_IMAGE_PROPERTY,
    update_package_in_spdx_sbom,
    update_sbom_name_and_namespace,
)
from mobster.image import Image
from mobster.sbom.cyclonedx import get_component


async def update_component_in_cyclonedx_sbom(
    sbom_wrapped: CycloneDX1BomWrapper, image: Image, is_builder_image: bool
) -> CycloneDX1BomWrapper:
    """
    Update the CycloneDX SBOM with the image reference.

    The reference to the image is added to the SBOM in the form of a component and
    purl is added to the metadata.

    Args:
        sbom_wrapped (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.
        is_builder_image (bool): Is the image used in a builder stage for the component?

    Returns:
        dict: Updated SBOM with the image reference added.
    """
    image_component = get_component(image)

    if is_builder_image:
        # Add builder image property to image_component
        image_component.properties.add(Property(**BUILDER_IMAGE_PROPERTY))
        # Add the builder image component to formulation section
        sbom_wrapped.formulation.append(
            {"components": CycloneDX1BomWrapper.get_component_dicts([image_component])}
        )
    else:
        sbom_wrapped.sbom.metadata.component = image_component
        sbom_wrapped.sbom.components.add(image_component)
        # Mark other components as dependencies. This also
        # allows having the same `metadata.component.bom-ref`
        # and `components[].bom-ref` for the root component
        sbom_wrapped.sbom.dependencies.add(
            Dependency(
                ref=image_component.bom_ref,
                dependencies=[
                    Dependency(component.bom_ref)
                    for component in sbom_wrapped.sbom.components
                    if component != image_component
                ],
            )
        )

    return sbom_wrapped


async def extend_sbom_with_image_reference(
    sbom: CycloneDX1BomWrapper | Document, image: Image, is_builder_image: bool
) -> None:
    """
    Extend the SBOM with the image reference.
    Based on the SBOM format, the image reference is added to the SBOM in
    a different way.

    Args:
        sbom (dict): SBOM in JSON format.
        image (Image): An instance of the Image class that represents the image.
        is_builder_image (bool): Is the image used in a builder stage for the component?

    Returns:
        None: Nothing is returned, changes are performed in-place.
    """
    if isinstance(sbom, CycloneDX1BomWrapper):
        await update_component_in_cyclonedx_sbom(sbom, image, is_builder_image)
    elif isinstance(sbom, Document):
        await update_package_in_spdx_sbom(sbom, image, is_builder_image)
        if not is_builder_image:
            await update_sbom_name_and_namespace(sbom, image)
