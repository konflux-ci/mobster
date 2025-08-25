"""A module for re-generating component SBOM documents."""

import logging

from mobster.cmd.regenerate.base import RegenerateCommand

LOGGER = logging.getLogger(__name__)


class RegenerateComponentCommand(RegenerateCommand):
    """Command to re-generate a component SBOM document."""

    async def execute(self) -> None:
        """Re-generate an SBOM document for a component."""
        LOGGER.info("Starting component SBOM re-generation.")
        self.init()
        await self.regenerate_sboms_set()
        self.exit_code = 0

