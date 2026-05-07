"""SBOM enriching utilities"""

import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cyclonedx.model.component import Component
from packageurl import PackageURL

from mobster import utils
from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.enrich.merge_utils import (
    _merge_dicts,
    _merge_union,
    _merge_union_by_key,
    _prefer_a,
)

logger = logging.getLogger(__name__)


# pylint: disable=no-member
def all_purls(
    sbom_items: Sequence[Component],
) -> dict[PackageURL, int]:
    """
    returns all the purls for a Sequence of SBOM Items
        - all the purls for a sequence of Components if the SBOM is CDX
    """

    purls_dict = {}
    for index, item in enumerate(sbom_items):
        component_item: Component = item
        if component_item.purl is None:
            continue
        purl = component_item.purl
        purls_dict[purl] = index
    return purls_dict


def compare_purls(p1: PackageURL, p2: PackageURL) -> bool:
    """
    the OWASP tool trunacetes the version to 8 characters, so check that
    - p1 and p2 have the same type
    - p1 and p2 have the same name
    - p2 is contained within p1
    """
    return (
        p1.type == p2.type
        and p1.name == p2.name
        and p1.version is not None
        and p2.version is not None
        and (p1.version.startswith(p2.version) or p2.version.startswith(p1.version))
    )


def general_enrich(
    enrich_func: Any, sbom_a: CycloneDX1BomWrapper, sbom_b: CycloneDX1BomWrapper
) -> None:
    """
    generic enrich function for all SBOMItem
    args:
    - enrich_func: the function for enriching target_packages and incoming_components
    - target_packages: the packages of the SBOM that is being enriched
    - incoming_components: components of the SBOM to extract the enrichment data from
    """
    items_a = sbom_a.sbom.components
    component_a_purls = all_purls(items_a)
    for component_b in sbom_b.sbom.components:
        for component_a_purl in component_a_purls:  # pylint: disable=consider-using-dict-items
            if compare_purls(component_a_purl, component_b.purl):
                index = component_a_purls[component_a_purl]
                component_a = items_a[index]

                if sbom_b.model_cards:
                    model_card = sbom_b.model_cards.get(component_b.purl)

                    # we've already established that the purls are the same so
                    # for consistency, replace the purl in sbom_b for the purl
                    # with the full version

                    # if the versions were the same in the first place, this does
                    # nothing
                    sbom_b.model_cards.pop(component_b.purl, None)
                    component_b.purl = component_a_purl
                    if model_card is not None:
                        sbom_b.model_cards[component_b.purl] = model_card

                    enrich_func(sbom_a, sbom_b, component_a, component_b)


def add_back_model_card(sbom: CycloneDX1BomWrapper, raw_sbom: dict[str, Any]) -> None:
    """
    loads a modelCard dictionary into a Bom object from a raw (dictionary) sbom.
    This is because cyclonedx-tools-lib does not support modelCard yet, therefore
    it must be added back manually
    """
    raw_components = raw_sbom.get("components", [])
    for component_obj, raw_comp in zip(
        sbom.sbom.components, raw_components, strict=False
    ):
        if "modelCard" in raw_comp:
            component_obj.model_card = raw_comp["modelCard"]


def is_cyclonedx(sbom: dict[str, Any]) -> bool:
    """
    checks if the sbom is in cyclonedx format
    """
    return sbom.get("bomFormat") == "CycloneDX"


class SBOMEnricher(ABC):  # pylint: disable=too-few-public-methods
    """
    Abstract base class for SBOM enrichers.
    Subclasses should implement the enrich method for specific SBOM formats.
    """

    @abstractmethod
    async def enrich(
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

    async def enrich(
        self,
        target_sbom: dict[str, Any],
        incoming_sbom: dict[str, Any],
    ) -> CycloneDX1BomWrapper:
        """
        Enrich a CycloneDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        sbom_a: CycloneDX1BomWrapper = CycloneDX1BomWrapper.from_dict(target_sbom)

        try:
            if is_cyclonedx(incoming_sbom):
                sbom_b: CycloneDX1BomWrapper = CycloneDX1BomWrapper.from_dict(
                    incoming_sbom, False
                )

                sbom_a.sbom.metadata.tools.components.add(self.get_owasp_tool(sbom_b))
                general_enrich(self.enrich_components, sbom_a, sbom_b)
            else:
                raise ValueError("ERROR: expecting the incoming SBOM to be CycloneDX")
        except ValueError as e:
            logger.exception(e)

        return sbom_a

    def get_owasp_tool(self, sbom: CycloneDX1BomWrapper) -> Any:
        """
        Finds the OWASP tool in the SBOM and returns the component
        """
        for tool in sbom.sbom.metadata.tools.components:
            if tool.name == "owasp-aibom-generator":
                return tool
        raise ValueError("OWASP tool not found in SBOM metadata")

    def _merge_fields(
        self,
        target: dict[str, Any],
        incoming: dict[str, Any],
        field_specs: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Merge incoming into target field-by-field according to field_specs.
        Args:
            target (dict[str, Any]): the target SBOM to enrich
            incoming (dict[str, Any]): The SBOM to extract fields from and add to target
            field_specs (dict[str, Any]):
                { field_name: merge_strategy_callable }
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

    def enrich_components(
        self,
        sbom_a: CycloneDX1BomWrapper,
        sbom_b: CycloneDX1BomWrapper,
        component_a: Component,
        component_b: Component,
    ) -> Any:
        """
        Merge model card and external references of component_b into component_a
        """
        self.merge_model_cards(sbom_a, sbom_b, component_a)

        if component_b.external_references:
            if component_a.external_references:
                unique = [
                    er
                    for er in component_b.external_references
                    if er not in component_a.external_references
                ]

                component_a.external_references.update(unique)
            else:
                component_a.external_references = component_b.external_references

    def merge_model_cards(
        self,
        sbom_a: CycloneDX1BomWrapper,
        sbom_b: CycloneDX1BomWrapper,
        component_a: Component,
    ) -> Any:
        """
        This represents the main "enriching" step of enriching a CDX SBOM with
        the OWASP produced SBOM. This only looks in the modelCard field,
        as this is where the OWASP tool populates the AI fields from Hugging Face.
        Method: merge the model card of incoming_component into target_component.
        If target has no model card, the incoming one is adopted wholesale.
        """
        if component_a.purl is None:
            return
        sbom_b_model_card = sbom_b.model_cards[component_a.purl]
        if not sbom_a.model_cards or component_a.purl not in sbom_a.model_cards:
            sbom_a.model_cards = {component_a.purl: sbom_b_model_card}
            return

        model_card_fields = {
            "properties": _merge_union,
            "quantativeAnalysis": _merge_union,
            "modelParameters": self.combine_model_parameters,
            "considerations": self.combine_considerations,
        }

        incoming_model_card = sbom_a.model_cards[component_a.purl]
        sbom_a.model_cards[component_a.purl] = self._merge_fields(
            sbom_b_model_card,
            incoming_model_card,
            model_card_fields,
        )

        # check if any of the top level modelCard fields populated with null, pop them
        for field in model_card_fields:
            if not sbom_b_model_card[field]:
                sbom_b_model_card.pop(field, None)

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
            # so we need to go one more step down to combine the fields
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


def _create_enricher(target_sbom: dict[str, Any]) -> SBOMEnricher:
    """
    Creates a Enricher for the given SBOMs.
    Raises:
        if the sbom is not in cyclonedx format, raises ValueError
    """

    if is_cyclonedx(target_sbom):
        return CycloneDXEnricher()
    raise ValueError("ERROR, expected SBOM to be in CycloneDX")


async def enrich_sbom(target_sbom: Path, incoming_sbom: Path) -> CycloneDX1BomWrapper:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for enriching two SBOMs.
    The incoming SBOM is expected to a a CycloneDX SBOM (as OWASP only produces SBOMs
    in CycloneDX format)
    The target SBOM is expected to a a CycloneDX SBOM (as Konflux only produces
    SBOMs in SPDX 2.3, which does not support AI fields)

    Args:
        target_sbom: the base CDX SBOM file to be enriched.
        incoming_sbom: the CDX SBOM to extract the enrichment data from.

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
    enricher = _create_enricher(target_sbom_loaded)

    result: CycloneDX1BomWrapper = await enricher.enrich(
        target_sbom_loaded, incoming_sbom_loaded
    )
    return result
