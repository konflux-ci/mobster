"""A module for generating SBOM documents for OCI artifact images."""

import logging
from typing import Any

import yaml
from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.artifact import Artifact
from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx

LOGGER = logging.getLogger(__name__)


class GenerateOciArtifactCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document for an OCI artifact.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for oci artifact.
        """
        with open(self.cli_args.oci_copy_yaml, encoding="utf-8") as oci_copy_file:
            oci_copy_data = yaml.safe_load(oci_copy_file)

        artifacts = [Artifact(**artifact) for artifact in oci_copy_data["artifacts"]]
        oci_image = Image.from_image_index_url_and_digest(
            self.cli_args.image_pullspec,
            self.cli_args.image_digest,
        )

        sbom = self.to_sbom(oci_image, artifacts)

        self._content = sbom
        return self.content

    def to_sbom(self, oci_image: Image, artifacts: list[Artifact]) -> Any:
        """
        Generate an SBOM document for oci artifact.

        Args:
            oci_image (Image): Image object representing the OCI artifact.
            artifacts (list[Artifact]): List of Artifact objects associated with the
            OCI image.

        Returns:
            Any: An SBOM document object in the specified format (CycloneDX or SPDX)
            based on the command line arguments.
        """
        if self.cli_args.sbom_type == "cyclonedx":
            return self.to_cyclonedx(oci_image, artifacts)
        return self.to_spdx(oci_image, artifacts)

    def to_cyclonedx(self, oci_image: Image, artifacts: list[Artifact]) -> Any:
        """
        Generate a CycloneDX SBOM document for oci artifact image.

        Args:
            oci_image (Image): Image object representing the OCI artifact.
            artifacts (list[Artifact]): List of Artifact objects associated with the
            OCI image.

        Returns:
            Any: An SBOM document object in cyclonedx format.
        """

        root_component = cyclonedx.get_component(oci_image)

        # Create CycloneDX BOM and assign it the root component
        document = Bom()
        document.metadata.tools.components.add(cyclonedx.get_tools_component())
        document.metadata.component = root_component

        artifact_components = [
            cyclonedx.get_component_from_artifact(artifact) for artifact in artifacts
        ]

        for artifact_component in artifact_components:
            document.components.add(artifact_component)

        document.components.add(root_component)

        # Add the dependencies between the root component and artifact components
        document.dependencies.add(
            Dependency(
                ref=root_component.bom_ref,
                dependencies=[
                    Dependency(artifact.bom_ref) for artifact in artifact_components
                ],
            )
        )
        return document

    def to_spdx(self, oci_image: Image, artifacts: list[Artifact]) -> Any:
        """
        Generate a SPDX SBOM document for oci artifact image.

        Args:
            oci_image (Image): Image object representing the OCI artifact.
            artifacts (list[Artifact]): List of Artifact objects associated with the
            OCI image.

        Returns:
            Any: An SBOM document object in SPDX format.
        """
        packages = [spdx.get_image_package(oci_image, oci_image.propose_spdx_id())]
        artifact_packages = [
            spdx.get_package_from_artifact(artifact) for artifact in artifacts
        ]
        packages.extend(artifact_packages)
        relationships = [
            spdx.get_root_package_relationship(oci_image.propose_spdx_id()),
        ]
        for artifact in artifacts:
            relationships.append(
                self.get_artifact_relationship(
                    artifact.propose_spdx_id(), oci_image.propose_spdx_id()
                )
            )
        document = Document(
            creation_info=spdx.get_creation_info(oci_image.propose_sbom_name()),
            packages=packages,
            relationships=relationships,
        )

        return document

    def get_artifact_relationship(
        self, spdx_id: str, oci_image_spdx_id: str
    ) -> Relationship:
        """
        Get a relationship for the artifact in relation to the main image.
        This relationship indicates artifact is contained within the OCI image.

        Args:
            spdx_id (str): An SPDX ID for the artifact.
            oci_image_spdx_id: str: An SPDX ID for the main image.

        Returns:
            Relationship: A SPDX relationship object for the child image.
        """
        return Relationship(
            spdx_element_id=oci_image_spdx_id,
            relationship_type=RelationshipType.CONTAINS,
            related_spdx_element_id=spdx_id,
        )
