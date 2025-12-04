"""
Module for wrapping CycloneDX SBOMs in a way that is fully supported.

If CycloneDX python lib starts supporting the `formulation` field,
this can be mostly removed.
"""

import json
from dataclasses import dataclass, field
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from mobster import get_mobster_version
from mobster.sbom.cyclonedx import get_manufacturer


@dataclass
class CycloneDX1BomWrapper:
    """
    Wrapper dataclass that drags the currently unsupported field,
    `formulation` along the SBOM. Can be removed and rewritten
    after this field is fully supported by the official library.
    """

    sbom: Bom
    formulation: list[dict[str, Any]] = field(default_factory=list)
    model_cards: dict[PackageURL, dict[str, Any]] = field(default_factory=dict)

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
        if self.model_cards:
            for index, component in enumerate(self.sbom.components):
                if component.purl and component.purl in self.model_cards:
                    model_card = self.model_cards[component.purl]
                    sbom_dict["components"][index]["modelCard"] = model_card
        return sbom_dict  # type: ignore[no-any-return]

    @staticmethod
    def from_dict(
        sbom_dict: dict[str, Any], generate: bool = True
    ) -> "CycloneDX1BomWrapper":
        """
        Loads the object from a dictionary.
        Args:
            sbom_dict (dict[str, Any]): A JSON-like dictionary.
        Returns:
            CycloneDX1BomWrapper: the initialized object of this class.
        """
        formulation = sbom_dict.pop("formulation", [])
        model_cards = {}
        for comp in sbom_dict.get("components", []):
            if comp.get("modelCard", []):
                purl = comp.get("purl")
                if purl:
                    as_string = PackageURL.from_string(purl)
                    model_cards[as_string] = comp.get("modelCard", [])
                else:
                    raise ValueError(
                        "Error, expected a component with a model card",
                        "to have a PURL",
                    )
        # pylint: disable=no-member
        bom_object = CycloneDX1BomWrapper(
            Bom.from_json(sbom_dict),  # type: ignore[attr-defined]
            formulation,
            model_cards,
        )

        if generate:
            bom_object.sbom.metadata.tools.components.add(
                Component(
                    version=get_mobster_version(),
                    name="Mobster",
                    type=ComponentType.APPLICATION,
                )
            )
            bom_object.sbom.metadata.manufacturer = get_manufacturer()

        return bom_object
