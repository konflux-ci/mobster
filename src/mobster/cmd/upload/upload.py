"""Upload command for the the Mobster application."""

import asyncio
import glob
import logging
import os
import time
from pathlib import Path
from typing import Any

import pydantic

from mobster.cmd.base import Command
from mobster.cmd.upload.oidc import OIDCClientCredentials
from mobster.cmd.upload.tpa import TPAClient

LOGGER = logging.getLogger(__name__)


class UploadReport(pydantic.BaseModel):
    """Upload report containing successful and failed uploads.

    Attributes:
        success: List of file paths that were successfully uploaded.
        failure: List of file paths that failed to upload.
    """

    success: list[Path]
    failure: list[Path]

    @staticmethod
    def build_report(results: list[tuple[Path, bool]]) -> "UploadReport":
        """Build an upload report from upload results.

        Args:
            results: List of tuples containing file path and success status.

        Returns:
            UploadReport instance with successful and failed uploads categorized.
        """
        success = [path for path, ok in list(results) if ok]
        failure = [path for path, ok in results if not ok]

        return UploadReport(success=success, failure=failure)


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
        sbom_files: list[Path] = []
        if self.cli_args.from_dir:
            sbom_files = self.gather_sboms(self.cli_args.from_dir)
        elif self.cli_args.file:
            sbom_files = [self.cli_args.file]

        workers = self.cli_args.workers if self.cli_args.from_dir else 1

        report = await self.upload(
            auth, self.cli_args.tpa_base_url, sbom_files, workers
        )
        if self.cli_args.report:
            print(report.model_dump_json())

    @staticmethod
    async def upload_sbom_file(
        sbom_file: Path,
        auth: OIDCClientCredentials,
        tpa_url: str,
        semaphore: asyncio.Semaphore,
    ) -> bool:
        """
        Upload a single SBOM file to TPA using HTTP client.

        Args:
            sbom_file (Path): Absolute path to the SBOM file to upload
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
            filename = sbom_file.name
            start_time = time.time()
            try:
                await client.upload_sbom(sbom_file)
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
        sbom_files: list[Path],
        workers: int,
    ) -> UploadReport:
        """
        Upload SBOM files to TPA given a directory or a file.

        Args:
            auth (OIDCClientCredentials): Authentication object for the TPA API
            tpa_url (str): Base URL for the TPA API
            sbom_files (list[Path]): List of SBOM file paths to upload
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

        results = await asyncio.gather(*tasks)
        self.success = all(results)

        LOGGER.info("Upload complete")
        return UploadReport.build_report(list(zip(sbom_files, results, strict=True)))

    async def save(self) -> bool:  # pragma: no cover
        """
        Save the command state.
        """
        return self.success

    @staticmethod
    def gather_sboms(dirpath: Path) -> list[Path]:
        """
        Recursively gather all files from a directory path.

        Args:
            dirpath: The directory path to search for files.

        Returns:
            A list of Path objects representing all files found recursively
            within the given directory, including files in subdirectories.
            Directories themselves are excluded from the results.
        """
        return [
            Path(path)
            for path in glob.glob(str(dirpath / "**" / "*"), recursive=True)
            if Path(path).is_file()
        ]
