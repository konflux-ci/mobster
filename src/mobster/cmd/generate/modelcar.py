"""A module for generating SBOM documents for OCI index images."""

import logging
from argparse import ArgumentError
from pathlib import Path
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.writer.write_utils import convert

from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.cmd.generate.oci_image.spdx_utils import normalize_and_load_sbom
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx
from mobster.utils import load_sbom_from_json

LOGGER = logging.getLogger(__name__)


def _spdx_purls(package: dict[str, Any]) -> list[str]:
    return [
        ref["referenceLocator"]
        for ref in package.get("externalRefs", [])
        if ref.get("referenceType") == "purl"
    ]


def merge_syft_packages_into_modelcar_spdx(
    modelcar_sbom: dict[str, Any],
    syft_sboms: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Merge packages from Syft SPDX SBOMs into a modelcar composition SBOM.

    Packages already present (matched by purl) are skipped. New packages are
    linked to the modelcar root with CONTAINS relationships.
    """
    existing_ids = {pkg["SPDXID"] for pkg in modelcar_sbom.get("packages", [])}
    existing_purls = {
        purl
        for pkg in modelcar_sbom.get("packages", [])
        for purl in _spdx_purls(pkg)
    }
    root_id = next(
        (
            rel["relatedSpdxElement"]
            for rel in modelcar_sbom.get("relationships", [])
            if rel.get("relationshipType") == "DESCRIBES"
        ),
        None,
    )

    for syft in syft_sboms:
        for pkg in syft.get("packages", []):
            purls = _spdx_purls(pkg)
            if purls and any(purl in existing_purls for purl in purls):
                continue
            pkg = dict(pkg)
            spdx_id = pkg["SPDXID"]
            if spdx_id in existing_ids:
                spdx_id = f"{spdx_id}-from-syft"
                pkg["SPDXID"] = spdx_id
            modelcar_sbom.setdefault("packages", []).append(pkg)
            existing_ids.add(spdx_id)
            existing_purls.update(purls)
            if root_id:
                modelcar_sbom.setdefault("relationships", []).append(
                    {
                        "spdxElementId": root_id,
                        "relationshipType": "CONTAINS",
                        "relatedSpdxElement": spdx_id,
                    }
                )

    return modelcar_sbom


class GenerateModelcarCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document for a model car task.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for modelcar.
        """
        modelcar = Image.from_oci_artifact_reference(self.cli_args.modelcar_image)
        base = Image.from_oci_artifact_reference(self.cli_args.base_image)
        model = Image.from_oci_artifact_reference(self.cli_args.model_image)

        sbom = await self.to_sbom(modelcar, base, model)
        if self.cli_args.from_syft:
            sbom = await self._merge_from_syft(sbom)

        self._content = sbom
        return self.content

    async def _merge_from_syft(self, sbom: Any) -> Document:
        """
        Merge Syft SPDX package inventory into the modelcar composition SBOM.
        """
        if self.cli_args.sbom_type != "spdx":
            raise ArgumentError(
                None,
                "--from-syft is only supported with --sbom-type spdx",
            )
        if not isinstance(sbom, Document):
            raise TypeError("Expected SPDX Document when merging --from-syft")

        modelcar_dict = convert(sbom, DocumentConverter())  # type: ignore[no-untyped-call]
        syft_sboms = [
            await load_sbom_from_json(Path(path)) for path in self.cli_args.from_syft
        ]
        LOGGER.info(
            "Merging packages from %d Syft SBOM(s) into modelcar SBOM",
            len(syft_sboms),
        )
        merged = merge_syft_packages_into_modelcar_spdx(modelcar_dict, syft_sboms)
        return await normalize_and_load_sbom(merged)

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
