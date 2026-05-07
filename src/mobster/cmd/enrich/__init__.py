"""A module for enriching SBOM documents."""

__all__ = ["EnrichCommand"]

import json
import logging
from pathlib import Path
from typing import Any

from mobster.cmd.base import Command
from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.enrich import enrich_sbom

logging.captureWarnings(True)  # CDX validation uses `warn()`
LOGGER = logging.getLogger(__name__)


class EnrichCommand(Command):
    """
    Command to enrich an SBOM document.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self._content: Any = None

    @staticmethod
    async def dump_sbom_to_dict(
        sbom: CycloneDX1BomWrapper,
    ) -> dict[str, Any]:
        """
        Dumps an SBOM object representation to a dictionary
        Args:
            sbom (CycloneDX1BomWrapper):
                the SBOM object to dump
        Returns:
            dict[str, Any]: The SBOM dumped to a dictionary
        """
        return sbom.to_dict()

    @property
    def name(self) -> str:
        """
        Name of the augment command used for logging purposes.
        """
        return "EnrichCommand"

    async def _enrich_sboms(
        self,
    ) -> CycloneDX1BomWrapper:
        """
        Handles the input SBOM files
        Returns:
            dict[str, Any]: Enriched/loaded SBOM dictionary.
        Raises:
            ArgumentError: If the base sbom or enrichment is not provided.
        """

        return await enrich_sbom(
            Path(self.cli_args.sbom), Path(self.cli_args.enrichment_file)
        )

    async def execute(self) -> Any:
        """
        Enrich an SBOM document.
        """
        LOGGER.debug("Enriching SBOM document ")

        self._content = await self._enrich_sboms()
        return self._content

    async def save(self) -> None:
        """
        This method is now a no-op since SBOMs are written directly during the
        enrichment process to avoid accumulating SBOMs in memory.
        """
        out = await EnrichCommand.dump_sbom_to_dict(self._content)
        outfile: Path = self.cli_args.output
        if outfile is not None:
            with open(outfile, "w", encoding="utf-8") as write_stream:
                json.dump(out, write_stream)
        else:
            print(json.dumps(out))
