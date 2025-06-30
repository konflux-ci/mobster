"""A command execution module for generating SBOM documents."""

import json
import logging
from abc import ABC
from typing import Any

from cyclonedx.output.json import JsonV1Dot5
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.cmd.base import Command

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


class GenerateCommandWithOutputTypeSelector(GenerateCommand, ABC):
    """
    A base class for generating SBOM documents with an output selector.
    This class extends GenerateCommand to include an output selector to support
    different SBOM formats (CycloneDX, SPDX, etc.).
    """

    async def save(self) -> None:
        """
        Convert document to JSON and save it to a file.
        """
        if self.cli_args.output and self._content:
            LOGGER.info("Saving SBOM document to '%s'", self.cli_args.output)
            if self.cli_args.sbom_type == "cyclonedx":
                with open(str(self.cli_args.output), "w", encoding="utf-8") as file:
                    outputter = JsonV1Dot5(self._content)
                    file.write(outputter.output_as_string(indent=2))
            else:
                write_file(
                    self._content,
                    str(self.cli_args.output),
                    validate=True,
                )
