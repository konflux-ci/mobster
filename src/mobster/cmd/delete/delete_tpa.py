"""Delete TPA command for the the Mobster application."""

import logging
from typing import Any

from mobster.cmd.base import Command
from mobster.cmd.upload.tpa import get_tpa_default_client

LOGGER = logging.getLogger(__name__)


class TPADeleteCommand(Command):
    """
    Command to delete a file from the TPA.
    """

    def __init__(self, cli_args: Any, *args: Any, **kwargs: Any):
        super().__init__(cli_args, *args, **kwargs)
        self.exit_code = 1

    async def execute(self) -> Any:
        """
        Execute the command to delete SBOMs from the TPA.
        """
        tpa_client = get_tpa_default_client(self.cli_args.tpa_base_url)

        sboms = tpa_client.list_sboms(query=self.cli_args.query, sort="ingested")

        async for sbom in sboms:
            if self.cli_args.dry_run:
                LOGGER.info("Would delete SBOM: %s (%s)", sbom.id, sbom.name)
                continue
            await tpa_client.delete_sbom(sbom.id)
            LOGGER.info("Deleted SBOM:  %s (%s)", sbom.id, sbom.name)
        self.exit_code = 0

    async def save(self) -> None:
        """
        Save the command's state.
        """
