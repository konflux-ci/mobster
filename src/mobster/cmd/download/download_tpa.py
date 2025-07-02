"""Download TPA command for the the Mobster application."""

import logging
from typing import Any

from mobster import utils
from mobster.cmd.base import Command
from mobster.cmd.upload.tpa import get_tpa_default_client

LOGGER = logging.getLogger(__name__)


class TPADownloadCommand(Command):
    """
    Command to download a file to the TPA.
    """

    def __init__(self, cli_args: Any, *args: Any, **kwargs: Any):
        super().__init__(cli_args, *args, **kwargs)
        self.exit_code = 1

    async def execute(self) -> Any:
        """
        Execute the command to download a file(s) to the TPA.
        """

        tpa_client = get_tpa_default_client(
            self.cli_args.tpa_base_url,
        )

        sboms = tpa_client.list_sboms(query=self.cli_args.query, sort="ingested")

        async for sbom in sboms:
            # normalize the name to be a valid filename
            name = utils.normalize_file_name(sbom.name)
            local_path = self.cli_args.output / f"{name}.json"

            await tpa_client.download_sbom(sbom.id, local_path)
        self.exit_code = 0

    async def save(self) -> None:
        """
        Save the command's state.
        """
