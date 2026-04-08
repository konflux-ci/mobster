"""
Module for wrapping CycloneDX SBOMs in a way that is fully supported.

If CycloneDX python lib starts supporting the `formulation` field,
this can be mostly removed.
"""

import json
from dataclasses import dataclass, field
from typing import Any

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion

from mobster import get_mobster_version
from mobster.cmd.generate.oci_image.base_image_utils import (
    get_images_and_their_annotations,
)
from mobster.image import Image
from mobster.sbom.cyclonedx import get_component, get_manufacturer


@dataclass
class CycloneDX1BomWrapper:
    """
    Wrapper dataclass that drags the currently unsupported field,
    `formulation` along the SBOM. Can be removed and rewritten
    after this field is fully supported by the official library.
    """

    sbom: Bom
    formulation: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def get_component_dicts(components: list[Component]) -> list[dict[str, Any]]:
        """
        Transforms component objects into dictionaries.
        Args:
            components (list[cyclonedx.model.bom.Component]): components to convert

        Returns:
            list[dict[str, Any]]: JSON-like representation of the components.
        """
        dummy_bom = Bom(components=components)
        dummy_wrapper = CycloneDX1BomWrapper(dummy_bom)
        dummy_dict = dummy_wrapper.to_dict()
        return dummy_dict.get("components")  # type: ignore[return-value]

    def to_dict(self) -> dict[str, Any]:
        """
        Gets a dictionary representation of the SBOM.
        Returns:
            dict: JSON-like Representation of the SBOM.
        """
        outputter = make_outputter(
            bom=self.sbom,
            output_format=OutputFormat.JSON,
            schema_version=SchemaVersion.V1_6,
        )
        sbom_json = outputter.output_as_string()
        sbom_dict = json.loads(sbom_json)
        if self.formulation:
            sbom_dict["formulation"] = self.formulation
        return sbom_dict  # type: ignore[no-any-return]

    @staticmethod
    def from_dict(sbom_dict: dict[str, Any]) -> "CycloneDX1BomWrapper":
        """
        Loads the object from a dictionary.
        Args:
            sbom_dict (dict[str, Any]): A JSON-like dictionary.
        Returns:
            CycloneDX1VomWrapper: the initialized object of this class.
        """
        formulation = sbom_dict.pop("formulation", [])
        # pylint: disable=no-member
        bom_object = CycloneDX1BomWrapper(
            Bom.from_json(sbom_dict),  # type: ignore[attr-defined]
            formulation,
        )
        bom_object.sbom.metadata.tools.components.add(
            Component(
                version=get_mobster_version(),
                name="Mobster",
                type=ComponentType.APPLICATION,
            )
        )
        bom_object.sbom.metadata.manufacturer = get_manufacturer()
        return bom_object


async def get_cdx_components_from_base_images(
    base_images_refs: list[str | None], base_images: dict[str, Image]
) -> list[Component]:
    """
    Transforms the list of base images and their mapping to
    an Image object into a list of CDX Components.
    Args:
        base_images_refs (list[str]):
            list of image references, the last one is the parent image.
        base_images (dict[str, Image]):
            mapping of those references to Image objects.

    Returns:
        list[cyclonedx.model.component.Component]:
            List of CDX components to be added to an SBOM.
    """
    components = []
    for image_component, annotations in await get_images_and_their_annotations(
        base_images_refs, base_images
    ):
        component = get_component(image_component)
        for annotation in annotations:
            component.properties.add(Property(**annotation))
        components.append(component)
    return components


async def extend_cdx_with_base_images(
    sbom_wrapper: CycloneDX1BomWrapper,
    base_image_refs: list[str | None],
    base_images: dict[str, Image],
) -> None:
    """
    Extend the CDX SBOM with the base images.
    Args:
        sbom_wrapper (CycloneDX1BomWrapper):
            SBOM to be edited.
        base_image_refs (list[str]):
            list of image references, the last one is the parent image.
        base_images (dict[str, Image]):
            mapping of those references to Image objects.

    Returns:
        None: Nothing is returned, changes are performed in-place.
    """
    components = await get_cdx_components_from_base_images(base_image_refs, base_images)
    sbom_wrapper.formulation.append(
        {"components": CycloneDX1BomWrapper.get_component_dicts(components)}
    )
