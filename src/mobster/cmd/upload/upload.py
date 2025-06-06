"""Upload command for the the Mobster application."""

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

from mobster.cmd.base import Command
from mobster.cmd.upload.oidc import OIDCClientCredentials
from mobster.cmd.upload.tpa import TPAClient

LOGGER = logging.getLogger(__name__)


class TPAUploadCommand(Command):
    """
    Command to upload a file to the TPA.
    """

    def __init__(self, cli_args: Any, *args: Any, **kwargs: Any):
        super().__init__(cli_args, *args, **kwargs)
        self.success = False

    async def execute(self) -> Any:
        """
        Execute the command to upload a file(s) to the TPA.
        """

        auth = OIDCClientCredentials(
            token_url=os.environ["MOBSTER_TPA_SSO_TOKEN_URL"],
            client_id=os.environ["MOBSTER_TPA_SSO_ACCOUNT"],
            client_secret=os.environ["MOBSTER_TPA_SSO_TOKEN"],
        )
        sbom_files = []
        if self.cli_args.from_dir:
            sbom_files = os.listdir(self.cli_args.from_dir)
        elif self.cli_args.file:
            sbom_files = [self.cli_args.file]

        workers = self.cli_args.workers if self.cli_args.file else 1

        await self.upload(auth, self.cli_args.tpa_base_url, sbom_files, workers)

    @staticmethod
    async def upload_sbom_file(
        sbom_file: str,
        auth: OIDCClientCredentials,
        tpa_url: str,
        semaphore: asyncio.Semaphore,
    ) -> bool:
        """
        Upload a single SBOM file to TPA using HTTP client.

        Args:
            sbom_file (str): Absolute path to the SBOM file to upload
            auth (OIDCClientCredentials): Authentication object for the TPA API
            tpa_url (str): Base URL for the TPA API
            semaphore (asyncio.Semaphore): A semaphore to limit the number
            of concurrent uploads
        """
        async with semaphore:
            client = TPAClient(
                base_url=tpa_url,
                auth=auth,
            )
            LOGGER.info("Uploading %s to TPA", sbom_file)
            sbom_filepath = Path(sbom_file)
            filename = sbom_filepath.name
            try:
                start_time = time.time()
                response = await client.upload_sbom(sbom_filepath)
                if response is None:
                    LOGGER.error(
                        "Failed to upload %s and took %s",
                        filename,
                        time.time() - start_time,
                    )
                return True
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(
                    "Error uploading %s and took %s", filename, time.time() - start_time
                )
                return False

    async def upload(
        self,
        auth: OIDCClientCredentials,
        tpa_url: str,
        sbom_files: list[str],
        workers: int,
    ) -> None:
        """
        Upload SBOM files to TPA given a directory or a file.

        Args:
            auth (OIDCClientCredentials): Authentication object for the TPA API
            tpa_url (str): Base URL for the TPA API
            sbom_files (list[str]): List of SBOM file paths to upload
            workers (int): Number of concurrent workers for uploading
        """

        LOGGER.info("Found %s SBOMs to upload", len(sbom_files))

        semaphore = asyncio.Semaphore(workers)

        tasks = [
            self.upload_sbom_file(
                sbom_file=sbom_file, auth=auth, tpa_url=tpa_url, semaphore=semaphore
            )
            for sbom_file in sbom_files
        ]

        self.success = all(await asyncio.gather(*tasks))

        LOGGER.info("Upload complete")

    async def save(self) -> bool:  # pragma: no cover
        """
        Save the command state.
        """
        return self.success
