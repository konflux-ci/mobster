"""A module for generating SBOM documents for OCI images."""

__all__ = ["EnrichImageCommand"]

import json
import logging
from argparse import ArgumentError
from pathlib import Path
from typing import Any

from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.writer.write_utils import convert

from mobster.cmd.base import Command
from mobster.sbom.enrich import enrich_sbom

logging.captureWarnings(True)  # CDX validation uses `warn()`
LOGGER = logging.getLogger(__name__)


class EnrichImageCommand(Command):
    """
    Command to enrich an SBOM document for an OCI image.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self._content: Any = None

    @staticmethod
    async def dump_model_card_to_dict(sbom: Bom, sbom_dict: dict[str, Any]) -> None:
        """
        dumps modelCard inside an sbom Bom object to json sbom_dict
        """
        index = 0
        for component in sbom.components:
            if hasattr(component, "model_card"):
                model_card = component.model_card
                sbom_dict["components"][index]["modelCard"] = model_card
            index += 1

    @staticmethod
    async def dump_sbom_to_dict(
        sbom: Document | Bom,
    ) -> dict[str, Any]:
        """
        Dumps an SBOM object representation to a dictionary
        Args:
            sbom (spdx_tools.spdx.model.document.Document | Bom):
                the SBOM object to dump
        Returns:
            dict[str, Any]: The SBOM dumped to a dictionary
        """
        if isinstance(sbom, Document):
            return convert(sbom, DocumentConverter())  # type: ignore[no-untyped-call]

        outputter = make_outputter(
            bom=sbom,
            output_format=OutputFormat.JSON,
            schema_version=SchemaVersion.V1_6,
        )
        sbom_json = outputter.output_as_string()
        sbom_dict: dict[str, Any] = json.loads(sbom_json)
        await EnrichImageCommand.dump_model_card_to_dict(sbom, sbom_dict)
        return sbom_dict

    @property
    def name(self) -> str:
        """
        Name of the augment command used for logging purposes.
        """
        return "EnrichImageCommand"

    async def _handle_bom_inputs(
        self,
    ) -> Bom | Document:
        """
        Handles the input SBOM files
        Returns:
            dict[str, Any]: Enriched/loaded SBOM dictionary.
        Raises:
            ArgumentError: If the base sbom or enrichment is not provided.
        """
        if (
            self.cli_args.sbom is None or self.cli_args.enrichment_file is None
            # and self.cli_args.image_pullspec is None
        ):
            raise ArgumentError(
                None,
                "Both sbom and the enrichment file must be provided",
            )

        return await enrich_sbom(
            Path(self.cli_args.sbom), Path(self.cli_args.enrichment_file)
        )

    async def execute(self) -> Any:
        """
        Enrich an SBOM document for OCI image.
        """
        LOGGER.debug("Enriching SBOM document for OCI image")

        self._content = await self._handle_bom_inputs()
        return self._content

    async def save(self) -> None:
        """
        This method is now a no-op since SBOMs are written directly during the
        enrichment process to avoid accumulating SBOMs in memory.
        """
        out = await self.dump_sbom_to_dict(self._content)
        outfile: Path = self.cli_args.output
        if outfile is not None:
            with open(outfile, "w", encoding="utf-8") as write_stream:
                json.dump(out, write_stream)
        else:
            print(json.dumps(out))
