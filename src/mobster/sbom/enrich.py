"""SBOM enriching utilities"""

import json
from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from spdx_tools.common.spdx_licensing import (  # type: ignore[import-untyped]
    spdx_licensing,
)
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package

from mobster import utils
from mobster.cmd.generate.oci_image import spdx_utils
from mobster.sbom import spdx


# pylint: disable=no-member
def purl_without_version(purl: PackageURL) -> PackageURL:
    """
    Returns the inputted purl without the version.
    Allows for equality of purls regardless of version
    """
    return purl._replace(version=None, qualifiers=None, subpath=None)


def all_purls(
    sbom_items: Sequence[Package] | Sequence[Component],
) -> dict[PackageURL, int]:
    """
    returns all the purls for a Sequence of SBOM Items
        - all the purls for a sequence of Components if the SBOM is CDX
        - all the purls for a sequence of Packages if the SBOM is in SPDX
    """

    purls_dict = {}
    is_package = isinstance(sbom_items[0], Package)
    for index, item in enumerate(sbom_items):
        if is_package:
            purl_str = spdx.get_package_purl(item)  # type: ignore[arg-type]
            if purl_str:
                purl = PackageURL.from_string(purl_str)
            else:
                continue
        else:
            component_item: Component = item  # type: ignore[assignment]
            if component_item.purl is None:
                continue
            purl = component_item.purl
        purls_dict[purl_without_version(purl)] = index
    return purls_dict


def general_enrich(
    enrich_func: Any, sbom: Document | Bom, incoming_components: Sequence[Component]
) -> None:
    """
    generic enrich function for all SBOMItem
    args:
    - enrich_func: the function for enriching target_packages and incoming_components
        (for example, SPDX-CDX will have a different function that SPDX-SPDX)
    - target_packages: the packages of the SBOM that is being enriched
    - incoming_components: components of the SBOM to extract the enrichment data from
    """
    items = sbom.packages if isinstance(sbom, Document) else sbom.components
    target_purls = all_purls(items)
    for component in incoming_components:
        if component.purl is None:
            continue
        incoming_versionless = purl_without_version(component.purl)
        if incoming_versionless in target_purls:
            index = target_purls[incoming_versionless]
            item_to_enrich = items[index]

            enrich_func(sbom, item_to_enrich, component)


def add_back_model_card(sbom: Bom, raw_sbom: dict[str, Any]) -> None:
    """
    loads a modelCard dictionary into a Bom object from a raw (dictionary) sbom.
    This is because cyclonedx-tools-lib does not support modelCard yet, therefore
    it must be added back manually
    """
    raw_components = raw_sbom.get("components", [])
    for component_obj, raw_comp in zip(sbom.components, raw_components, strict=False):
        if "modelCard" in raw_comp:
            component_obj.model_card = raw_comp["modelCard"]


def _merge_union(a: list[Any], b: list[Any]) -> list[Any]:
    """Append items from b not already in a."""
    return a + [p for p in b if p not in a]


def _prefer_a(a: Any, _b: Any) -> Any:
    return a


def _merge_dicts(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """b | a so that a's keys win."""
    return b | a


def _merge_union_by_key(key: str) -> Any:
    """Deduplicate a list of objects by a given identity key, preferring a's value."""

    def merge_by_key(
        a: list[dict[str, Any]], b: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        existing_keys = {item[key] for item in a if key in item}
        return a + [item for item in b if item.get(key) not in existing_keys]

    return merge_by_key


class SBOMEnricher(ABC):  # pylint: disable=too-few-public-methods
    """
    Abstract base class for SBOM enrichers.
    Subclasses should implement the enrich method for specific SBOM formats.
    """

    @abstractmethod
    def enrich(
        self,
        target_sbom: dict[str, Any],
        incoming_sbom: dict[str, Any],
    ) -> Any:  # pragma: no cover
        """
        Enrich two SBOMs.
        This method should be implemented by subclasses.
        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom
        Returns:
            dict[str, Any]: The enriched SBOM
        """
        raise NotImplementedError("Enrich method logic is implemented in subclasses.")


class CycloneDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for CycloneDX SBOMs.
    """

    # pylint: disable=invalid-overridden-method
    async def enrich(
        self,
        target_sbom: dict[str, Any],
        incoming_sbom: dict[str, Any],
    ) -> Bom:
        """
        Enrich a CycloneDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        sbom_a: Bom = Bom.from_json(target_sbom)  # type: ignore[attr-defined]
        # cyclonedx-tools-lib doesn't support modelCard, so need to manually add it
        # back (as a dictionary)
        add_back_model_card(sbom_a, target_sbom)

        try:
            if incoming_sbom.get("bomFormat") == "CycloneDX":
                sbom_b: Bom = Bom.from_json(incoming_sbom)  # type: ignore[attr-defined]
                add_back_model_card(sbom_b, incoming_sbom)

                # add tools
                sbom_a.metadata.tools.components.add(
                    Component(
                        name="OWASP AIBOM Generator",
                        type=ComponentType.APPLICATION,
                    )
                )
                general_enrich(self.merge_model_cards, sbom_a, sbom_b.components)
            else:
                raise ValueError("ERROR: expecting the incoming SBOM to be CycloneDX")
        except Exception as e:
            raise e

        return sbom_a

    def _merge_fields(
        self,
        target: dict[str, Any],
        incoming: dict[str, Any],
        field_specs: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Merge incoming into target field-by-field according to field_specs.

        field_specs: { field_name: merge_strategy_callable }
        Each callable has signature (a, b) -> merged and is only called when
        both sides are non-None (merge_general semantics preserved).
        """
        for field, strategy in field_specs.items():
            target_val = target.get(field)
            incoming_val = incoming.get(field)
            result = self.merge_general(
                target_val if target_val is not None else {},
                incoming_val if incoming_val is not None else {},
                strategy,
            )
            # make sure null value does not get populated in the final SBOM
            target[field] = result if result else target.pop(field, None)
        return target

    def merge_model_cards(
        self, _sbom: Bom, target_component: Component, incoming_component: Component
    ) -> Any:
        """
        This represents the main "enriching" step of enriching a CDX SBOM with
        the OWASP produced SBOM. This only looks in the modelCard field,
        as this is where the OWASP tool populates the AI fields from Hugging Face.
        Method: merge the model card of incoming_component into target_component.
        If target has no model card, the incoming one is adopted wholesale.
        """
        if not hasattr(incoming_component, "model_card"):
            return

        if not hasattr(target_component, "model_card"):
            model_card = incoming_component.model_card
            target_component.model_card = model_card  # type: ignore[attr-defined]
            return

        model_card_fields = {
            "properties": _merge_union,
            "quantativeAnalysis": _merge_union,
            "modelParameters": self.combine_model_parameters,
            "considerations": self.combine_considerations,
        }

        target_component.model_card = self._merge_fields(
            target_component.model_card,
            incoming_component.model_card,
            model_card_fields,
        )

        # check if any of the top level modelCard fields populated with null, pop them
        # if so
        for field in model_card_fields:
            if not target_component.model_card[field]:
                target_component.model_card.pop(field, None)

    def combine_model_parameters(
        self, param_a: dict[str, Any], param_b: dict[str, Any]
    ) -> dict[str, Any]:
        """
        combines the modelParameters field of the modelCard.
        """
        param_fields = {
            "approach": _merge_dicts,
            "task": _prefer_a,
            "architectureFamily": _prefer_a,
            "modelArchitecture": _prefer_a,
            "datasets": _merge_union_by_key("ref"),
            "inputs": _merge_union,
            "outputs": _merge_union,
        }
        return self._merge_fields(param_a, param_b, param_fields)

    def combine_considerations(
        self, cons_a: dict[str, Any], cons_b: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Combines the considerations field of the modelCard.
        """
        consideration_fields = {
            "users": _merge_union,
            "useCases": _merge_union,
            "technicalLimitations": _merge_union,
            "performanceTradeoffs": _merge_union,
            "ethicalConsiderations": _merge_union_by_key("name"),
            "fairnessAssessments": _merge_union_by_key("groupAtRisk"),
            # environmentalConsiderations is not a list (and has more subfields)
            # therefore we need to go one more step down to combine the fields
            "environmentalConsiderations": self.combine_environmental_considerations,
        }
        return self._merge_fields(cons_a, cons_b, consideration_fields)

    def merge_general(self, list_a: Any, list_b: Any, combine_func: Any) -> Any:
        """
        General merge helper that applies combine_func only when both lists are non-None
        """
        if list_b:
            if list_a:
                return combine_func(list_a, list_b)
            return list_b
        return list_a

    def combine_environmental_considerations(
        self, env_a: dict[str, Any], env_b: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Combines the environmentalConsiderations field of the modelCard.
        """
        return self._merge_fields(
            env_a,
            env_b,
            {
                "energyConsumptions": _merge_union,
            },
        )


class SPDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for SPDX SBOMs.
    """

    async def enrich(  # pylint: disable=invalid-overridden-method
        self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]
    ) -> Document:
        """
        Enrich a SPDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            Document: The enriched SBOM
        """

        # passing in False because we don't want to add mobster to tools (it would
        # be repetitive, this step is always going to be called after generate)
        sbom_a: Document = await spdx_utils.normalize_and_load_sbom(target_sbom, False)
        sbom_b: Bom = Bom.from_json(incoming_sbom)  # type: ignore[attr-defined]

        # cyclonedx-tools-lib doesn't support modelCard, so need to manually add it
        # back (as a dictionary)
        add_back_model_card(sbom_b, incoming_sbom)

        try:
            if incoming_sbom.get("bomFormat") == "CycloneDX":
                new_tool = Actor(
                    actor_type=ActorType.TOOL, name="OWASP AIBOM Generator"
                )
                sbom_a.creation_info.creators.append(new_tool)

                incoming_components = sbom_b.components
                general_enrich(self.enrich_package, sbom_a, incoming_components)
            else:
                raise ValueError("ERROR: expecting the incoming SBOM to be CycloneDX")
        except Exception as e:
            raise e

        return sbom_a

    def enrich_package(  # pylint: disable=too-many-locals
        self, sbom: Document, package: Package, component: Component
    ) -> None:
        """
        adds all data from a CDX component modelCard to an SPDX package.
        This only looks in the modelCard field, as this is where the OWASP tool
        populates the AI fields from Hugging Face
        This function uses a chart that has equivalents
        for every AI CDX field to SPDX 3.0 field.
        However, Hermeto and Syft only produce up to version 2.3,
        which doesn't support AI fields.
        So, this first converts the keyword to SPDX 3.0,
        then adds the field as an annotation.
        When support for SPDX 3.0 exists, this should instead
        add to the AI fields section of the document
        """

        # load the AI field Mappings for CDX to SPDX
        script_path = Path(__file__).resolve()
        script_dir = script_path.parent

        try:
            with open(
                f"{script_dir}/enrich_tools/SPDXmappingAI.json", encoding="utf-8"
            ) as f:
                ai_mappings = json.load(f)
        except Exception as e:
            print(f"Error opening file: {e}")
            raise e

        if hasattr(component, "model_card"):
            model_card = component.model_card
            for field in model_card["properties"]:
                field_name, field_value = field["name"], field["value"]

                # check for any top level fields (supplier, description, and licensing)

                if field_name == "suppliedBy" and package.supplier is None:
                    package.supplier = Actor(
                        actor_type=ActorType.ORGANIZATION, name=field_value
                    )
                elif field_name == "description" and package.description is None:
                    package.description = field_value
                elif field_name == "licenses" and package.license_concluded is None:
                    package.license_concluded = spdx_licensing.parse(field_value)

                # check for any AI specific fields
                if field_name in ai_mappings:
                    spdx_ai_field_name = ai_mappings[field_name]["SPDX_Equivalent"]
                    new_annotator = Actor(
                        actor_type=ActorType.TOOL, name="OWASP AIBOM Generator"
                    )

                    annotation = Annotation(
                        spdx_id=package.spdx_id,
                        annotator=new_annotator,
                        annotation_type=AnnotationType.OTHER,
                        annotation_date=datetime.now(tz=timezone.utc),
                        annotation_comment=f"{spdx_ai_field_name} : {field_value}",
                    )
                    sbom.annotations.append(annotation)


def _create_enricher(target_sbom: dict[str, Any]) -> SBOMEnricher:
    """
    Creates a Enricher for the given SBOMs.
    """

    if target_sbom.get("bomFormat") == "CycloneDX":
        return CycloneDXEnricher()
    if "spdxVersion" in target_sbom:
        return SPDXEnricher()

    raise ValueError("ERROR, expected SBOM to be either CycloneDX or SPDX")


async def enrich_sbom(
    target_sbom: Path, incoming_sbom: Path | None = None
) -> Bom | Document:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for enriching two SBOMs.
    The incoming SBOM is expected to a a CycloneDX SBOM (as OWASP only produces SBOMs
    in CycloneDX format)
    The target SBOM can be either SPDX or CDX

    Args:
        target_sbom: the base SBOM file to be enriched. This can be of format SPDX & CDX
        incoming_sbom: the SBOM to extract the enrichment data from.
        This can be of format SPDX, CDX, or a JSON

    Returns:
        The enriched SBOM

    Raises:
        ValueError: If the target_sbom and incoming_sbom are not present
    """

    if not target_sbom or not incoming_sbom:
        raise ValueError("""A target SBOM path and an incoming
                         SBOM is required to enrich an SBOM.""")

    target_sbom_loaded = await utils.load_sbom_from_json(target_sbom)
    incoming_sbom_loaded = await utils.load_sbom_from_json(incoming_sbom)
    # we only need the type of the target SBOM to create the enricher
    try:
        enricher = _create_enricher(target_sbom_loaded)
    except Exception as e:
        raise e
    result: Bom | Document = await enricher.enrich(
        target_sbom_loaded, incoming_sbom_loaded
    )
    return result
