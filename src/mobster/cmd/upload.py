"""Upload command for the the Mobster application."""

import logging
from typing import Any

from mobster.cmd.base import Command

LOGGER = logging.getLogger(__name__)


class TPAUploadCommand(Command):
    """
    Command to upload a file to the TPA.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(args, **kwargs)

    async def execute(self) -> Any:
        """
        Execute the command to upload a file to the TPA.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Uploading SBOM(s) to TPA")
        return None

    async def save(self) -> bool:
        """
        Save the command state.
        """
        # Placeholder for the actual implementation
        return False
