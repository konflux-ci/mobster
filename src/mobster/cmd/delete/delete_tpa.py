"""Delete TPA command for the the Mobster application."""

import asyncio
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
        async with get_tpa_default_client(self.cli_args.tpa_base_url) as client:
            # Use larger pages to reduce list calls and a semaphore to bound concurrency
            sboms = client.list_sboms(
                query=self.cli_args.query, sort="ingested", page_size=200
            )

            semaphore = asyncio.Semaphore(10)
            delete_tasks: list[asyncio.Task[Any]] = []

            async def _delete(sbom_id: str, sbom_name: str) -> None:
                async with semaphore:
                    if self.cli_args.dry_run:
                        LOGGER.info("Would delete SBOM: %s (%s)", sbom.id, sbom.name)
                        return
                    await client.delete_sbom(sbom_id)
                    LOGGER.info("Deleted SBOM:  %s (%s)", sbom_id, sbom_name)

            async for sbom in sboms:
                delete_tasks.append(asyncio.create_task(_delete(sbom.id, sbom.name)))

            if delete_tasks:
                await asyncio.gather(*delete_tasks)
        self.exit_code = 0

    async def save(self) -> None:
        """
        Save the command's state.
        """
