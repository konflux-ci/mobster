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

        self._content: Any = None

    @property
    def content(self) -> Any:
        """
        Get the content of the SBOM document.
        """
        return self._content

    async def save(self) -> bool:
        """
        Save the SBOM document to a file if the output argument is provided.
        """
        if self.cli_args.output:
            LOGGER.debug("Saving SBOM document to '%s'", self.cli_args.output)
            with open(self.cli_args.output, "w", encoding="utf8") as output_file:
                json.dump(self.content, output_file, indent=2)
        return True
