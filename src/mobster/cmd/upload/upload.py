"""Upload command for the the Mobster application."""

import asyncio
import glob
import logging
import os
import time
from enum import Enum
from pathlib import Path
from typing import Any

import pydantic

from mobster.cmd.base import Command
from mobster.cmd.upload.oidc import OIDCClientCredentials, RetryExhaustedException
from mobster.cmd.upload.tpa import TPAClient

LOGGER = logging.getLogger(__name__)


class UploadExitCode(Enum):
    """
    Enumeration of possible exit codes from the upload command.
    """

    ERROR = 1
    TRANSIENT_ERROR = 2


class UploadReport(pydantic.BaseModel):
    """Upload report containing successful and failed uploads.

    Attributes:
        success: List of file paths that were successfully uploaded.
        failure: List of file paths that failed to upload.
    """

    success: list[Path]
    failure: list[Path]

    @staticmethod
    def build_report(
        results: list[tuple[Path, BaseException | None]],
    ) -> "UploadReport":
        """Build an upload report from upload results.

        Args:
            results: List of tuples containing file path and either an
                exception (failure) or None (success).

        Returns:
            UploadReport instance with successful and failed uploads categorized.
        """
        success = [path for path, result in results if result is None]
        failure = [
            path for path, result in results if isinstance(result, BaseException)
        ]

        return UploadReport(success=success, failure=failure)


class TPAUploadCommand(Command):
    """
    Command to upload a file to the TPA.
    """

    async def execute(self) -> Any:
        """
        Execute the command to upload a file(s) to the TPA.
        """

        auth = TPAUploadCommand.get_oidc_auth()
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
    def get_oidc_auth() -> OIDCClientCredentials | None:
        """
        Get OIDC client credentials from environment variables.

        Returns:
            OIDCClientCredentials: Client credentials if auth is enabled.
            None: If MOBSTER_TPA_AUTH_DISABLE is set to "true".
        """
        if os.environ.get("MOBSTER_TPA_AUTH_DISABLE", "false").lower() == "true":
            return None

        return OIDCClientCredentials(
            token_url=os.environ["MOBSTER_TPA_SSO_TOKEN_URL"],
            client_id=os.environ["MOBSTER_TPA_SSO_ACCOUNT"],
            client_secret=os.environ["MOBSTER_TPA_SSO_TOKEN"],
        )

    @staticmethod
    async def upload_sbom_file(
        sbom_file: Path,
        auth: OIDCClientCredentials | None,
        tpa_url: str,
        semaphore: asyncio.Semaphore,
    ) -> None:
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
                LOGGER.info("Successfully uploaded %s to TPA", sbom_file)
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(
                    "Error uploading %s and took %s", filename, time.time() - start_time
                )
                raise

    async def upload(
        self,
        auth: OIDCClientCredentials | None,
        tpa_url: str,
        sbom_files: list[Path],
        workers: int,
    ) -> UploadReport:
        """
        Upload SBOM files to TPA given a directory or a file.

        Args:
            auth (OIDCClientCredentials | None): Authentication object for the TPA API
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

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.set_exit_code(results)

        LOGGER.info("Upload complete")
        return UploadReport.build_report(list(zip(sbom_files, results, strict=True)))

    def set_exit_code(self, results: list[BaseException | None]) -> None:
        """
        Set the exit code based on the upload results. If all exceptions found
        are RetryExhaustedException, the exit code is
        UploadExitCode.TransientError. If at least one exception is not the
        RetryExhaustedException, the exit code is UploadExitCode.Error.

        Args:
            results: List of results from upload operations, either None for success
                or BaseException for failure.
        """
        non_transient_error = False
        for res in results:
            if isinstance(res, RetryExhaustedException):
                self.exit_code = UploadExitCode.TRANSIENT_ERROR.value
            elif isinstance(res, BaseException):
                non_transient_error = True

        if non_transient_error:
            self.exit_code = UploadExitCode.ERROR.value

    async def save(self) -> None:  # pragma: no cover
        """
        Save the command state.
        """

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

        Raises:
            FileNotFoundError: If the supplied directory doesn't exist
        """
        if not dirpath.exists():
            raise FileNotFoundError(f"The directory {dirpath} doesn't exist.")

        return [
            Path(path)
            for path in glob.glob(str(dirpath / "**" / "*"), recursive=True)
            if Path(path).is_file()
        ]
