"""A module for generating SBOM documents for OCI ModelCar images."""

import json
import logging
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from cyclonedx.output.json import JsonV1Dot5
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.writer.write_utils import convert

from mobster import syft
from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.cmd.generate.oci_image.spdx_utils import normalize_and_load_sbom
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx
from mobster.sbom.merge import CDXComponent, SPDXPackage

LOGGER = logging.getLogger(__name__)


def merge_syft_packages_into_modelcar_spdx(
    modelcar_sbom: dict[str, Any],
    syft_sbom: dict[str, Any],
    parent_id: str,
) -> dict[str, Any]:
    """
    Merge packages from a Syft SPDX SBOM into a modelcar composition SBOM.

    Packages already present (matched by purl via ``SPDXPackage.all_purls``)
    are skipped — if any Syft purl matches an existing one, the whole package
    is skipped (aliases of the same package). Packages without an SPDXID or
    without a purl are skipped. New packages are linked to ``parent_id``
    (typically the base image) with CONTAINS relationships.
    """
    existing_ids = {
        pkg["SPDXID"] for pkg in modelcar_sbom.get("packages", []) if pkg.get("SPDXID")
    }
    existing_purls = {
        str(purl)
        for pkg in modelcar_sbom.get("packages", [])
        for purl in SPDXPackage(pkg).all_purls()
    }

    for pkg in syft_sbom.get("packages", []):
        if "SPDXID" not in pkg:
            LOGGER.warning("Skipping Syft package without SPDXID: %s", pkg.get("name"))
            continue
        syft_pkg = SPDXPackage(pkg)
        purls = [str(purl) for purl in syft_pkg.all_purls()]
        if not purls:
            LOGGER.warning(
                "Skipping Syft package %s (%s): no purl for deduplication",
                pkg.get("name"),
                pkg["SPDXID"],
            )
            continue
        if any(purl in existing_purls for purl in purls):
            continue
        pkg_copy = dict(pkg)
        original_id = pkg_copy["SPDXID"]
        spdx_id = original_id
        counter = 0
        while spdx_id in existing_ids:
            suffix = "-from-syft" if counter == 0 else f"-from-syft-{counter}"
            spdx_id = f"{original_id}{suffix}"
            counter += 1
        pkg_copy["SPDXID"] = spdx_id
        modelcar_sbom.setdefault("packages", []).append(pkg_copy)
        existing_ids.add(spdx_id)
        existing_purls.update(purls)
        modelcar_sbom.setdefault("relationships", []).append(
            {
                "spdxElementId": parent_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )

    return modelcar_sbom


def merge_syft_components_into_modelcar_cdx(
    modelcar_sbom: dict[str, Any],
    syft_sbom: dict[str, Any],
    parent_ref: str,
) -> dict[str, Any]:
    """
    Merge components from a Syft CycloneDX SBOM into a modelcar composition SBOM.

    New components are linked under ``parent_ref`` (typically the base image)
    via ``dependencies[].dependsOn``. Duplicate purls are skipped.
    """
    components = list(modelcar_sbom.get("components") or [])
    existing_refs, existing_purls = _cdx_existing_refs_and_purls(
        modelcar_sbom, components
    )

    added_refs: list[str] = []
    for component in syft_sbom.get("components") or []:
        purl = CDXComponent(component).purl()
        if purl is None:
            LOGGER.warning(
                "Skipping Syft component %s: no purl for deduplication",
                component.get("name"),
            )
            continue
        purl_str = str(purl)
        if purl_str in existing_purls:
            continue

        comp_copy = dict(component)
        bom_ref = _unique_cdx_bom_ref(
            comp_copy.get("bom-ref") or f"syft-{purl_str}", existing_refs
        )
        comp_copy["bom-ref"] = bom_ref
        components.append(comp_copy)
        existing_refs.add(bom_ref)
        existing_purls.add(purl_str)
        added_refs.append(bom_ref)

    modelcar_sbom["components"] = components
    if added_refs:
        _attach_cdx_depends_on(modelcar_sbom, parent_ref, added_refs)
    return modelcar_sbom


def _cdx_existing_refs_and_purls(
    modelcar_sbom: dict[str, Any],
    components: list[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    existing_refs = {
        ref for c in components if isinstance(ref := c.get("bom-ref"), str)
    }
    metadata_component = (modelcar_sbom.get("metadata") or {}).get("component") or {}
    if isinstance(meta_ref := metadata_component.get("bom-ref"), str):
        existing_refs.add(meta_ref)
    existing_purls = {
        str(purl) for c in components if (purl := CDXComponent(c).purl()) is not None
    }
    if (meta_purl := CDXComponent(metadata_component).purl()) is not None:
        existing_purls.add(str(meta_purl))
    return existing_refs, existing_purls


def _unique_cdx_bom_ref(original_ref: str, existing_refs: set[str]) -> str:
    bom_ref = original_ref
    counter = 0
    while bom_ref in existing_refs:
        suffix = "-from-syft" if counter == 0 else f"-from-syft-{counter}"
        bom_ref = f"{original_ref}{suffix}"
        counter += 1
    return bom_ref


def _attach_cdx_depends_on(
    modelcar_sbom: dict[str, Any],
    parent_ref: str,
    added_refs: list[str],
) -> None:
    dependencies = list(modelcar_sbom.get("dependencies") or [])
    parent_dep = next((d for d in dependencies if d.get("ref") == parent_ref), None)
    if parent_dep is None:
        parent_dep = {"ref": parent_ref, "dependsOn": []}
        dependencies.append(parent_dep)
    depends_on = list(parent_dep.get("dependsOn") or [])
    for ref in added_refs:
        if ref not in depends_on:
            depends_on.append(ref)
    parent_dep["dependsOn"] = depends_on
    modelcar_sbom["dependencies"] = dependencies


class GenerateModelcarCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document for a model car task.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for modelcar, then scan the base image with
        Syft and merge its package inventory under the base image node.
        """
        modelcar = Image.from_oci_artifact_reference(self.cli_args.modelcar_image)
        base = Image.from_oci_artifact_reference(self.cli_args.base_image)
        model = Image.from_oci_artifact_reference(self.cli_args.model_image)

        sbom = await self.to_sbom(modelcar, base, model)
        sbom = await self._merge_base_syft_inventory(sbom, base)

        self._content = sbom
        return self.content

    async def save(self) -> None:
        """
        Save the SBOM. CycloneDX may be a merged dict after Syft inventory merge.
        """
        if not self.cli_args.output or self._content is None:
            return
        if isinstance(self._content, dict):
            LOGGER.info("Saving SBOM document to '%s'", self.cli_args.output)
            with open(str(self.cli_args.output), "w", encoding="utf-8") as file:
                json.dump(self._content, file, indent=2)
            return
        await super().save()

    async def _merge_base_syft_inventory(self, sbom: Any, base: Image) -> Any:
        """
        Scan the base image with Syft and merge packages under the base node.
        """
        LOGGER.info("Scanning base image with Syft: %s", base.reference)
        if isinstance(sbom, Bom):
            syft_sbom = await syft.scan_image(
                base.reference, output_format=syft.CYCLONEDX_JSON
            )
            composition = json.loads(JsonV1Dot5(sbom).output_as_string())
            return merge_syft_components_into_modelcar_cdx(
                composition,
                syft_sbom,
                base.propose_cyclonedx_bom_ref(),
            )

        if isinstance(sbom, Document):
            syft_sbom = await syft.scan_image(
                base.reference, output_format=syft.SPDX_JSON
            )
            modelcar_dict = convert(sbom, DocumentConverter())  # type: ignore[no-untyped-call]
            merged = merge_syft_packages_into_modelcar_spdx(
                modelcar_dict,
                syft_sbom,
                parent_id=base.propose_spdx_id(),
            )
            return await normalize_and_load_sbom(merged)

        raise TypeError(
            "Expected CycloneDX Bom or SPDX Document when merging Syft "
            f"inventory, got {type(sbom).__name__}"
        )

    async def to_sbom(self, modelcar: Image, base: Image, model: Image) -> Any:
        """
        Generate an SBOM document for modelcar based on the provided images.

        Args:
            modelcar (Image): Image object representing the modelcar.
            base (Image): Image object representing the base image.
            model (Image): Image object representing the model image.

        Returns:
            Any: An SBOM document object in the specified format (CycloneDX or SPDX)
            based on the command line arguments.
        """
        if self.cli_args.sbom_type == "cyclonedx":
            return await self.to_cyclonedx(modelcar, base, model)
        return await self.to_spdx(modelcar, base, model)

    async def to_cyclonedx(self, modelcar: Image, base: Image, model: Image) -> Any:
        """
        Generate a CycloneDX SBOM document for modelcar based on the provided images.

        Args:
            modelcar (Image): Image object representing the modelcar.
            base (Image): Image object representing the base image.
            model (Image): Image object representing the model image.

        Returns:
            Any: A CycloneDX SBOM document object.
        """

        root_component = cyclonedx.get_component(modelcar)
        base_component = cyclonedx.get_component(base)
        model_component = cyclonedx.get_component(model)

        # Create CycloneDX BOM and assign it the root component
        document = Bom()
        document.metadata.tools.components.add(cyclonedx.get_tools_component())
        document.metadata.component = root_component
        document.metadata.manufacturer = cyclonedx.get_manufacturer()

        # Add the base and model components to the BOM
        document.components.add(base_component)
        document.components.add(model_component)
        document.components.add(root_component)

        # Add the dependencies between the root, base, and model components
        document.dependencies.add(
            Dependency(
                ref=root_component.bom_ref,
                dependencies=[
                    Dependency(base_component.bom_ref),
                    Dependency(model_component.bom_ref),
                ],
            )
        )
        return document

    async def to_spdx(self, modelcar: Image, base: Image, model: Image) -> Any:
        """
        Generate a SPDX SBOM document for modelcar based on the provided images.

        Args:
            modelcar (Image): Image object representing the modelcar.
            base (Image): Image object representing the base image.
            model (Image): Image object representing the model image.

        Returns:
            Any: A SPDX SBOM document object.
        """
        packages = [
            spdx.get_image_package(modelcar, modelcar.propose_spdx_id()),
            spdx.get_image_package(base, base.propose_spdx_id()),
            spdx.get_image_package(model, model.propose_spdx_id()),
        ]
        relationships = [
            spdx.get_root_package_relationship(
                modelcar.propose_spdx_id(),
            ),
            await self.get_modelcar_descendant_image_relationship(
                modelcar.propose_spdx_id(),
                base.propose_spdx_id(),
            ),
            await self.get_modelcar_descendant_image_relationship(
                modelcar.propose_spdx_id(),
                model.propose_spdx_id(),
            ),
        ]
        document = Document(
            creation_info=spdx.get_creation_info(modelcar.propose_sbom_name()),
            packages=packages,
            relationships=relationships,
        )

        return document

    async def get_modelcar_descendant_image_relationship(
        self, spdx_id: str, modelcar_spdx_id: str
    ) -> Relationship:
        """
        Get a relationship for the image in relation to the modelcar image.
        This relationship indicates that the modelcar image is
        a descendant of the image represented by spdx_id.

        Args:
            spdx_id (str): An SPDX ID for the descendaten image.
            modelcar_spdx_id: str: An SPDX ID for the modelcar image.

        Returns:
            Relationship: A SPDX relationship object for the child image.
        """
        return Relationship(
            spdx_element_id=spdx_id,
            relationship_type=RelationshipType.DESCENDANT_OF,
            related_spdx_element_id=modelcar_spdx_id,
        )
