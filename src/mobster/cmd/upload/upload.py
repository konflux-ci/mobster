"""Upload command for the the Mobster application."""

import asyncio
import glob
import logging
import os
import time
from dataclasses import dataclass
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


class TPAUploadSuccess(pydantic.BaseModel):
    """
    Object representing a successful TPA upload.

    Attributes:
        path: Filesystem path of the uploaded SBOM.
        urn: Uniform Resource Name in TPA of the uploaded SBOM.
    """

    path: Path
    urn: str


class TPAUploadReport(pydantic.BaseModel):
    """Upload report containing successful and failed uploads.

    Attributes:
        success: List of TPAUploadSuccess objects for SBOMs that were successfully
            uploaded.
        failure: List of file paths that failed to upload.
    """

    success: list[TPAUploadSuccess]
    failure: list[Path]

    @staticmethod
    def build_report(
        results: list[tuple[Path, BaseException | str]],
    ) -> "TPAUploadReport":
        """Build an upload report from upload results.

        Args:
            results: List of tuples containing file path and either an
                exception (failure) or str (success).

        Returns:
            TPAUploadReport instance with successful and failed uploads categorized.
        """
        success = [
            TPAUploadSuccess(path=path, urn=urn)
            for path, urn in results
            if isinstance(urn, str)
        ]
        failure = [
            path for path, result in results if isinstance(result, BaseException)
        ]

        return TPAUploadReport(success=success, failure=failure)


@dataclass
class UploadConfig:
    """
    Configuration to use when uploading SBOMs to TPA.

    Attributes:
        auth: Optional OIDCClientCredentials object
        base_url: TPA base URL to use
        workers: number of maximum concurrent uploads
        labels: mapping of TPA label keys to label values for uploaded SBOMs
        paths: list of paths to SBOMs to upload
    """

    auth: OIDCClientCredentials | None
    base_url: str
    workers: int
    labels: dict[str, str]
    paths: list[Path]


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

        config = UploadConfig(
            auth=auth,
            base_url=self.cli_args.tpa_base_url,
            paths=sbom_files,
            workers=workers,
            labels=self.cli_args.labels,
        )

        report = await self.upload(config)
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
        labels: dict[str, str],
    ) -> str:
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
                resp = await client.upload_sbom(sbom_file, labels=labels)
                LOGGER.info("Successfully uploaded %s to TPA", sbom_file)
                return resp
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(
                    "Error uploading %s and took %s", filename, time.time() - start_time
                )
                raise

    async def upload(
        self,
        config: UploadConfig,
    ) -> TPAUploadReport:
        """
        Upload SBOM files to TPA given a directory or a file.

        Args:
            auth (OIDCClientCredentials | None): Authentication object for the TPA API
            tpa_url (str): Base URL for the TPA API
            sbom_files (list[Path]): List of SBOM file paths to upload
            workers (int): Number of concurrent workers for uploading
        """

        LOGGER.info("Found %s SBOMs to upload", len(config.paths))

        semaphore = asyncio.Semaphore(config.workers)

        tasks = [
            self.upload_sbom_file(
                sbom_file=sbom_file,
                auth=config.auth,
                tpa_url=config.base_url,
                semaphore=semaphore,
                labels=config.labels,
            )
            for sbom_file in config.paths
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.set_exit_code(results)

        LOGGER.info("Upload complete")
        return TPAUploadReport.build_report(
            list(zip(config.paths, results, strict=True))
        )

    def set_exit_code(self, results: list[BaseException | str]) -> None:
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
