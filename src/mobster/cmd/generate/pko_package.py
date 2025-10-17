"""A module for generating SBOM documents for pko packages."""

import logging
from typing import Any

from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
)

from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector
from mobster.image import Image
from mobster.sbom import cyclonedx, spdx

LOGGER = logging.getLogger(__name__)


class GeneratePkoPackageCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM document that describes a pko package.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document that describes a pko package resource
        defined by the given cli args.
        """

        image = Image.from_image_index_url_and_digest(
            self.cli_args.package_pullspec,
            self.cli_args.package_digest,
        )

        sbom = await self.to_sbom(image)

        self._content = sbom
        return self.content

    async def to_sbom(self, image: Image) -> Any:
        """
        Generate an SBOM document that describes a
        pko package defined by the given cli args.

        Args:
            image (Image): Image that is described by the generated SBOM.

        Returns:
            Any: An SBOM document object in the specified format (CycloneDX or SPDX)
                 based on the command line arguments.
        """

        url = self.cli_args.url

        if self.cli_args.sbom_type == "cyclonedx":
            return await self.to_cyclonedx(image, url)
        return await self.to_spdx(image, url)

    async def to_cyclonedx(self, image: Image, url: str) -> Any:
        """
        Generate a cyclonedx SBOM document that describes a pko package.

        Args:
            image (Image): Image that is described by the generated SBOM.
            url (str): VCS reference URL.

        Returns:
            Any: A CycloneDX SBOM document object.
        """

        package_component = cyclonedx.get_component(image)
        package_component.external_references.add(
            ExternalReference(url=XsUri(url), type=ExternalReferenceType.VCS)
        )

        document = Bom()
        document.metadata.tools.components.add(cyclonedx.get_tools_component())
        document.metadata.component = package_component
        document.components.add(package_component)

        return document

    async def to_spdx(self, image: Image, url: str) -> Any:
        """
        Generate a SPDX SBOM document that describes a pko package.

        Args:
            image (Image): Image that is described by the generated SBOM.
            url (str): VCS reference URL.

        Returns:
            Any: A SPDX SBOM document object.
        """

        ref = ExternalPackageRef(
            category=ExternalPackageRefCategory.OTHER,
            reference_type="vcs",
            locator=url,
        )

        package = spdx.get_image_package(image, image.propose_spdx_id())
        package.external_references.append(ref)  # pylint: disable=E1101

        document = Document(
            creation_info=spdx.get_creation_info("package"),
            packages=[package],
        )
        pkg_ref = spdx.get_root_package_relationship(package.spdx_id)
        document.relationships.append(pkg_ref)  # pylint: disable=E1101

        return document
