"""A module for generating SBOM documents for OCI ModelCar images."""

import logging
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.extracted_licensing_info import ExtractedLicensingInfo
from spdx_tools.spdx.model.package import (
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster import syft
from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.cmd.generate.oci_image.spdx_utils import normalize_and_load_sbom
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx

LOGGER = logging.getLogger(__name__)


def _spdx_package_purls(package: Package) -> list[str]:
    return [
        ref.locator
        for ref in package.external_references
        if (
            ref.category == ExternalPackageRefCategory.PACKAGE_MANAGER
            and ref.reference_type == "purl"
            and ref.locator
        )
    ]


def merge_syft_packages_into_modelcar_spdx(
    modelcar_sbom: Document,
    syft_sbom: Document,
    parent_id: str,
) -> Document:
    """
    Merge packages from a Syft SPDX Document into a modelcar composition Document.

    Packages already present (matched by any purl) are skipped — if any Syft
    purl matches an existing one, the whole package is skipped. Packages
    without a purl are skipped. New packages are linked to ``parent_id``
    (typically the base image) with CONTAINS relationships.

    Also copies Syft ``extracted_licensing_info`` entries (by ``license_id``)
    so LicenseRef-* expressions on merged packages remain valid.
    """
    packages = list(modelcar_sbom.packages or [])
    existing_ids = {pkg.spdx_id for pkg in packages}
    existing_purls = {purl for pkg in packages for purl in _spdx_package_purls(pkg)}

    relationships = list(modelcar_sbom.relationships or [])
    for pkg in syft_sbom.packages or []:
        purls = _spdx_package_purls(pkg)
        if not purls:
            LOGGER.warning(
                "Skipping Syft package %s (%s): no purl for deduplication",
                pkg.name,
                pkg.spdx_id,
            )
            continue
        if any(purl in existing_purls for purl in purls):
            continue

        original_id = pkg.spdx_id
        spdx_id = original_id
        counter = 0
        while spdx_id in existing_ids:
            suffix = "-from-syft" if counter == 0 else f"-from-syft-{counter}"
            spdx_id = f"{original_id}{suffix}"
            counter += 1
        pkg.spdx_id = spdx_id
        packages.append(pkg)
        existing_ids.add(spdx_id)
        existing_purls.update(purls)
        relationships.append(
            Relationship(
                spdx_element_id=parent_id,
                relationship_type=RelationshipType.CONTAINS,
                related_spdx_element_id=spdx_id,
            )
        )

    modelcar_sbom.packages = packages
    modelcar_sbom.relationships = relationships
    modelcar_sbom.extracted_licensing_info = _merge_extracted_licensing_info(
        modelcar_sbom, syft_sbom
    )
    return modelcar_sbom


def _merge_extracted_licensing_info(
    modelcar_sbom: Document,
    syft_sbom: Document,
) -> list[ExtractedLicensingInfo]:
    """Union Syft extracted license refs into the modelcar document by license_id."""
    merged = list(modelcar_sbom.extracted_licensing_info or [])
    existing_ids = {info.license_id for info in merged if info.license_id}
    for info in syft_sbom.extracted_licensing_info or []:
        if not info.license_id or info.license_id in existing_ids:
            continue
        merged.append(info)
        existing_ids.add(info.license_id)
    return merged


def _cdx_component_ref(component: Component) -> str:
    return str(component.bom_ref)


def merge_syft_components_into_modelcar_cdx(
    modelcar_sbom: Bom,
    syft_sbom: Bom,
    parent_ref: str,
) -> Bom:
    """
    Merge components from a Syft CycloneDX Bom into a modelcar composition Bom.

    New components are linked under ``parent_ref`` (typically the base image)
    via dependencies. Duplicate purls are skipped.
    """
    existing_refs = {_cdx_component_ref(c) for c in modelcar_sbom.components}
    existing_purls = {str(c.purl) for c in modelcar_sbom.components if c.purl}
    if meta := modelcar_sbom.metadata.component:
        existing_refs.add(_cdx_component_ref(meta))
        if meta.purl:
            existing_purls.add(str(meta.purl))

    added_refs: list[BomRef] = []
    for component in syft_sbom.components:
        if component.purl is None:
            LOGGER.warning(
                "Skipping Syft component %s: no purl for deduplication",
                component.name,
            )
            continue
        purl_str = str(component.purl)
        if purl_str in existing_purls:
            continue

        original_ref = _cdx_component_ref(component) or f"syft-{purl_str}"
        bom_ref = original_ref
        counter = 0
        while bom_ref in existing_refs:
            suffix = "-from-syft" if counter == 0 else f"-from-syft-{counter}"
            bom_ref = f"{original_ref}{suffix}"
            counter += 1
        if bom_ref != original_ref:
            component.bom_ref.value = bom_ref

        modelcar_sbom.components.add(component)
        existing_refs.add(bom_ref)
        existing_purls.add(purl_str)
        added_refs.append(component.bom_ref)

    if added_refs:
        _attach_cdx_depends_on(modelcar_sbom, parent_ref, added_refs)
    return modelcar_sbom


def _attach_cdx_depends_on(
    modelcar_sbom: Bom,
    parent_ref: str,
    added_refs: list[BomRef],
) -> None:
    parent_dep = next(
        (dep for dep in modelcar_sbom.dependencies if str(dep.ref) == parent_ref),
        None,
    )
    if parent_dep is None:
        parent_dep = Dependency(ref=BomRef(parent_ref))
        modelcar_sbom.dependencies.add(parent_dep)
    for ref in added_refs:
        parent_dep.dependencies.add(Dependency(ref=ref))


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

    async def _merge_base_syft_inventory(self, sbom: Any, base: Image) -> Any:
        """
        Scan the base image with Syft and merge packages under the base node.
        """
        LOGGER.info("Scanning base image with Syft: %s", base.reference)
        if isinstance(sbom, Bom):
            syft_dict = await syft.scan_image(
                base.reference, output_format=syft.CYCLONEDX_JSON
            )
            # pylint: disable=no-member
            syft_bom = Bom.from_json(syft_dict)  # type: ignore[attr-defined]
            return merge_syft_components_into_modelcar_cdx(
                sbom,
                syft_bom,
                base.propose_cyclonedx_bom_ref(),
            )

        if isinstance(sbom, Document):
            syft_dict = await syft.scan_image(
                base.reference, output_format=syft.SPDX_JSON
            )
            syft_doc = await normalize_and_load_sbom(syft_dict, append_mobster=False)
            return merge_syft_packages_into_modelcar_spdx(
                sbom,
                syft_doc,
                parent_id=base.propose_spdx_id(),
            )

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
