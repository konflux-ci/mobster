"""A module for generating SBOM documents for OCI images."""

import logging
from typing import Any

from mobster.cmd.generate.base import GenerateCommandWithOutputTypeSelector

LOGGER = logging.getLogger(__name__)


class GenerateOciImageCommand(GenerateCommandWithOutputTypeSelector):
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
