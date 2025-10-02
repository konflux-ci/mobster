"""A module for generating SBOM documents for VCS sources."""

import logging
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import (
    Commit,
    Component,
    ComponentType,
)
from cyclonedx.model import ExternalReferenceType, ExternalReference

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from cmd.generate.base import GenerateCommandWithOutputTypeSelector

LOGGER = logging.getLogger(__name__)


class GenerateVCSCommand(GenerateCommandWithOutputTypeSelector):
    """
    Command to generate an SBOM that references a VCS resource.
    """

    async def execute(self) -> Any:
        """
        Generate an SBOM document that references a VCS resource defined by the given cli args.
        """

        sbom = await self.to_sbom()

        self._content = sbom
        return self.content

    async def to_sbom(self) -> Any:
        """
        Generate an SBOM document that references a VCS resource defined by the given cli args.

        Returns:
            Any: An SBOM document object in the specified format (CycloneDX or SPDX)
            based on the command line arguments.
        """

        name = self.cli_args.name
        url = self.cli_args.url

        if self.cli_args.sbom_type == "cyclonedx":
            return await self.to_cyclonedx(name, url)
        return await self.to_spdx(name, url)

    async def to_cyclonedx(self, name: str, url: str) -> Any:
        """
        Generate a cyclonedx SBOM document that references a VCS resource.

        Args:
            name (str): Name of the SBOM.
            url (str): VCS reference URL.

        Returns:
            Any: A CycloneDX SBOM document object.
        """

        document = Bom()
        document.metadata.tools.components.add(cyclonedx.get_tools_component())

        package_component = Component(
            type=ComponentType.CONTAINER,
            name=name,
            external_references=[ExternalReference(url=url, type=ExternalReferenceType.VCS)],
        )
        document.components.add(package_component)

        return document

    async def to_spdx(self, name: str, url: str) -> Any:
        """
        Generate a SPDX SBOM document that references a VCS resource.

        Args:
            name (str): Name of the SBOM.
            url (str): VCS reference URL.

        Returns:
            Any: A SPDX SBOM document object.
        """

        ref = ExternalPackageRef(
            category=ExternalPackageRefCategory.OTHER,
            reference_type="vcs",
            locator=url,
        )
        
        package = Package(
            spdx_id=f"SPDXRef-Package-{name}",
            download_location=SpdxNoAssertion(),
            name=name,
            supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
            license_declared=SpdxNoAssertion(),
            files_analyzed=False,
            external_references=[ref],
        )

        document = Document(
            creation_info=spdx.get_creation_info(name),
            packages=[package],
        )

        return document
