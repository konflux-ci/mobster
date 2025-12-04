"""A module for generating SBOM documents for OCI images."""

__all__ = ["EnrichImageCommand"]

import json
import logging, os
from argparse import ArgumentError
import os
from pathlib import Path
from typing import Any

from mobster.sbom.enrich import enrich_sbom
from mobster.cmd.base import Command
from mobster.cmd.augment import SBOMRefDetail

logging.captureWarnings(True)  # CDX validation uses `warn()`
LOGGER = logging.getLogger(__name__)

class EnrichImageCommand(Command):
    """
    Command to generate an SBOM document for an OCI image.
    """
    @property
    def name(self) -> str:
        """
        Name of the augment command used for logging purposes.
        """
        return "EnrichImageCommand"

    async def _handle_bom_inputs(
        self,
    ) -> dict[str, Any]:
        """
        Handles the input SBOM files
        Returns:
            dict[str, Any]: Enriched/loaded SBOM dictionary.
        Raises:
            ArgumentError: If the base sbom or enrichment is not provided.
        """
        if (
            self.cli_args.sbom is None
            or self.cli_args.enrichment_file is None
            # and self.cli_args.image_pullspec is None
        ):
            raise ArgumentError(
                None,
                "Both sbom and the enrichment file must be provided",
            )

        return await enrich_sbom(Path(self.cli_args.sbom), Path(self.cli_args.enrichment_file))

    async def execute(self) -> Any:
        """
        Generate an SBOM document for OCI image.
        """
        LOGGER.debug("Generating SBOM document for OCI image")

        enriched_sbom_dict = await self._handle_bom_inputs()

        #TODO: for now just saves to a json file. Needs to save as an OCI artifact 
        #if an output path is provided, save there, otherwise save in current directory
        output_path = self.cli_args.output if self.cli_args.output else os.getcwd()
        
        with open(Path(output_path), 'w') as f:
            json.dump(enriched_sbom_dict, f, indent=2)

        return enriched_sbom_dict

    async def save(self) -> None:
        """
        This method is now a no-op since SBOMs are written directly during the
        enrichment process to avoid accumulating SBOMs in memory.
        """