"""A command execution module for generating SBOM documents."""

import json
import logging
from abc import ABC
from typing import Any

from mobster.cmd.base import Command

LOGGER = logging.getLogger(__name__)


class GenerateCommand(Command, ABC):
    """A base class for generating SBOM documents command."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self._content: dict[str, Any] | None = None

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

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI index.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Generating SBOM document for OCI index")
        self._content = {}
        return self.content


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
