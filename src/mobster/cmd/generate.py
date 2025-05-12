"""A command execution module for generating SBOM documents."""

import json
import logging
from abc import ABC
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.cmd.base import Command
from mobster.image import Image

LOGGER = logging.getLogger(__name__)


class GenerateCommand(Command, ABC):
    """A base class for generating SBOM documents command."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self._content: Any = None

    @property
    def content(self) -> Any:
        """
        Get the content of the SBOM document.
        """
        return self._content

    async def save(self) -> None:
        """
        Save the SBOM document to a file if the output argument is provided.
        """
        if self.cli_args.output:
            LOGGER.debug("Saving SBOM document to '%s'", self.cli_args.output)
            with open(self.cli_args.output, "w", encoding="utf8") as output_file:
                json.dump(self.content, output_file, indent=2)


class GenerateOciImageCommand(GenerateCommand):
    """
    Command to generate an SBOM document for an OCI image.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI image.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Generating SBOM document for OCI image")
        self._content = {}
        return self.content


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

    def get_package(self, image: Image, spdx_id: str) -> Package:
        """
        Transform the parsed image object into SPDX package object.


        Args:
            image (Image): A parsed image object.
            spdx_id (str): An SPDX ID for the image.

        Returns:
            Package: A package object representing the OCI image.
        """

        package = Package(
            spdx_id=spdx_id,
            name=image.name if not image.arch else f"{image.name}_{image.arch}",
            version=image.tag,
            download_location=SpdxNoAssertion(),
            supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
            license_declared=SpdxNoAssertion(),
            files_analyzed=False,
            external_references=[
                ExternalPackageRef(
                    category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                    reference_type="purl",
                    locator=image.purl(),
                )
            ],
            checksums=[
                Checksum(
                    algorithm=ChecksumAlgorithm.SHA256,
                    value=image.digest_hex_val,
                )
            ],
        )

        return package

    def get_index_image_relationship(self, spdx_id: str) -> Relationship:
        """
        Get a relationship for the OCI index image in relation to the SPDX document.
        This relationship indicates that the document describes the index image.

        Args:
            spdx_id (str): An SPDX ID for the index image.

        Returns:
            Relationship: A SPDX relationship object for the index image.
        """
        return Relationship(
            spdx_element_id=self.DOC_ELEMENT_ID,
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id=spdx_id,
        )

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

            arch_image = Image(
                arch=arch,
                name=index_image.name,
                digest=self.cli_args.index_image_digest,
                tag=index_image.tag,
                repository=index_image.repository,
            )
            spdx_id = arch_image.propose_spdx_id()
            package = self.get_package(
                arch_image,
                spdx_id,
            )
            relationship = self.get_child_image_relationship(spdx_id)

            packages.append(package)
            relationships.append(relationship)

        return packages, relationships

    def get_creation_info(self, index_image: Image) -> CreationInfo:
        """
        Create the creation information for the SPDX document.

        Args:
            index_image (Image): An OCI index image object.

        Returns:
            CreationInfo: A creation information object for the SPDX document.
        """
        sbom_name = f"{index_image.repository}@{index_image.digest}"
        return CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id=self.DOC_ELEMENT_ID,
            name=sbom_name,
            data_license="CC0-1.0",
            document_namespace="https://konflux-ci.dev/spdxdocs/"
            f"{index_image.name}-{index_image.tag}-{uuid4()}",
            creators=[
                Actor(ActorType.ORGANIZATION, "Red Hat"),
                Actor(ActorType.TOOL, "Konflux CI"),
                Actor(ActorType.TOOL, "Mobster"),
            ],
            created=datetime.now(timezone.utc),
        )

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI index in SPDX format.
        """
        LOGGER.info("Generating SBOM document for OCI index")

        index_image = Image.from_image_index_url_and_digest(
            self.cli_args.index_image_pullspec, self.cli_args.index_image_digest
        )

        main_package = self.get_package(index_image, self.INDEX_ELEMENT_ID)
        main_relationship = self.get_index_image_relationship(self.INDEX_ELEMENT_ID)
        component_packages, component_relationships = self.get_child_packages(
            index_image
        )

        # Assemble a complete SPDX document
        document = Document(
            creation_info=self.get_creation_info(index_image),
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


class GenerateProductCommand(GenerateCommand):
    """
    Command to generate an SBOM document for a product level.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for product.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Generating SBOM document for product")
        self._content = {}
        return self.content


class GenerateModelcarCommand(GenerateCommand):
    """
    Command to generate an SBOM document for a model car task.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for modelcar.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Generating SBOM document for modelcar")
        self._content = {}
        return self.content


class GenerateOciArtifactCommand(GenerateCommand):
    """
    Command to generate an SBOM document for an OCI artifact.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI artifact.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Generating SBOM document for OCI artifact")
        self._content = {}
        return self.content
