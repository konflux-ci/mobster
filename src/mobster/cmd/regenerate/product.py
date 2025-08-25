"""A module for re-generating SBOM documents for products."""

import logging

from mobster.cmd.regenerate.base import RegenerateCommand

LOGGER = logging.getLogger(__name__)


class RegenerateProductCommand(RegenerateCommand):
    """Command to re-generate a product-level SBOM document."""

    async def execute(self) -> None:
        """Re-generate an SBOM document for a product."""
        LOGGER.info("Starting product SBOM re-generation.")
        self.init()
        await self.regenerate_sboms_set()
        self.exit_code = 0

