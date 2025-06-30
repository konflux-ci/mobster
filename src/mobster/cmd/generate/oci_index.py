"""A module for generating SBOM documents for OCI index images."""

import json
import logging
from typing import Any

from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.cmd.generate.base import GenerateCommand
from mobster.image import Image
from mobster.sbom import spdx

LOGGER = logging.getLogger(__name__)


class GenerateOciIndexCommand(GenerateCommand):
    """
    Command to generate an SBOM document for an OCI index image.
    """

    INDEX_IMAGE_MANIFEST_MEDIA_TYPES = [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]

    IMAGE_MANIFEST_MEDIA_TYPES = [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]

    DOC_ELEMENT_ID = "SPDXRef-DOCUMENT"
    INDEX_ELEMENT_ID = "SPDXRef-image-index"

    def get_child_image_relationship(self, spdx_id: str) -> Relationship:
        """
        Get a relationship for the child image in relation to the OCI index image.
        This relationship indicates that the child image is
        a variant of the index image.

        Args:
            spdx_id (str): An SPDX ID for the child image.

        Returns:
            Relationship: A SPDX relationship object for the child image.
        """
        return Relationship(
            spdx_element_id=spdx_id,
            relationship_type=RelationshipType.VARIANT_OF,
            related_spdx_element_id=self.INDEX_ELEMENT_ID,
        )

    def get_child_packages(
        self, index_image: Image
    ) -> tuple[list[Package], list[Relationship]]:
        """
        Get child packages from the OCI index image.
        """
        packages = []
        relationships = []

        with open(self.cli_args.index_manifest_path, encoding="utf8") as manifest_file:
            index_manifest = json.load(manifest_file)

        if index_manifest["mediaType"] not in self.INDEX_IMAGE_MANIFEST_MEDIA_TYPES:
            raise ValueError(
                "Invalid input file detected, requires `buildah manifest inspect` json."
            )

        LOGGER.debug("Inspecting OCI index image: %s", index_manifest)

        for manifest in index_manifest["manifests"]:
            if manifest["mediaType"] not in self.IMAGE_MANIFEST_MEDIA_TYPES:
                LOGGER.warning(
                    "Skipping manifest with unsupported media type: %s",
                    manifest["mediaType"],
                )
                continue

            arch = manifest.get("platform", {}).get("architecture")
            LOGGER.info("Found child image with architecture: %s", arch)

            # assign actual image architecture once image SBOMs contain
            # the architecture in their purls
            arch_image = Image(
                digest=manifest["digest"],
                tag=index_image.tag,
                repository=index_image.repository,
                arch=None,
            )
            spdx_id = arch_image.propose_spdx_id()
            package = spdx.get_image_package(
                arch_image,
                spdx_id,
                package_name=f"{arch_image.name}_{arch}",
            )
            relationship = self.get_child_image_relationship(spdx_id)

            packages.append(package)
            relationships.append(relationship)

        return packages, relationships

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI index in SPDX format.
        """
        LOGGER.info("Generating SBOM document for OCI index")

        index_image = Image.from_image_index_url_and_digest(
            self.cli_args.index_image_pullspec, self.cli_args.index_image_digest
        )

        main_package = spdx.get_image_package(index_image, self.INDEX_ELEMENT_ID)
        main_relationship = spdx.get_root_package_relationship(self.INDEX_ELEMENT_ID)
        component_packages, component_relationships = self.get_child_packages(
            index_image
        )

        # Assemble a complete SPDX document
        sbom_name = f"{index_image.repository}@{index_image.digest}"
        document = Document(
            creation_info=spdx.get_creation_info(sbom_name),
            packages=[main_package] + component_packages,
            relationships=[main_relationship] + component_relationships,
        )

        self._content = document
        return self.content

    async def save(self) -> None:
        """
        Convert SPDX document to JSON and save it to a file.
        """
        if self.cli_args.output and self._content:
            LOGGER.info("Saving SBOM document to '%s'", self.cli_args.output)
            write_file(
                self._content,
                str(self.cli_args.output),
                validate=True,
            )
