"""A module for generating SBOM documents for OCI index images."""

import logging
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx

LOGGER = logging.getLogger(__name__)


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

        self._content = sbom
        return self.content

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
