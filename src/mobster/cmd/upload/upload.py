"""Upload command for the the Mobster application."""

import asyncio
import glob
import logging
import os
import posixpath
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pydantic

from mobster.cmd.base import Command
from mobster.cmd.upload.oidc import OIDCClientCredentials
from mobster.cmd.upload.tpa import TPAClient, TPATransientError

LOGGER = logging.getLogger(__name__)


class TPAUploadSuccess(pydantic.BaseModel):
    """
    Object representing a successful TPA upload.

    Attributes:
        path: Filesystem path of the uploaded SBOM.
        url: URL in TPA of the uploaded SBOM.
    """

    path: Path
    url: str


class TPAUploadFailure(pydantic.BaseModel):
    """
    Object representing a failed TPA upload.

    Attributes:
        path: Filesystem path of the SBOM that failed to upload.
        transient: Whether the failure was transient (retryable).
        message: Error message describing the failure.
    """

    path: Path
    transient: bool
    message: str


class TPAUploadReport(pydantic.BaseModel):
    """Upload report containing successful and failed uploads.

    Attributes:
        success: List of TPAUploadSuccess objects for SBOMs that were successfully
            uploaded.
        failure: List of file paths that failed to upload.
    """

    success: list[TPAUploadSuccess]
    failure: list[TPAUploadFailure]

    @property
    def transient_error_paths(self) -> list[Path]:
        """
        Get paths of files that failed with transient errors.

        Returns:
            List of Path objects for files that failed with transient errors.
        """
        return [failure.path for failure in self.failure if failure.transient]

    def get_non_transient_errors(self) -> list[tuple[Path, str]]:
        """
        Get list of tuples containing paths of files that failed to be uploaded
        and their error messages.
        """
        return [
            (failure.path, failure.message)
            for failure in self.failure
            if not failure.transient
        ]

    def has_non_transient_failures(self) -> bool:
        """
        Check if there are any non-transient failures.

        Returns:
            True if any failures are non-transient, False otherwise.
        """
        return any(not failure.transient for failure in self.failure)

    def has_transient_failures(self) -> bool:
        """
        Check if there are any transient failures.

        Returns:
            True if any failures are transient, False otherwise.
        """
        return any(failure.transient for failure in self.failure)

    def has_failures(self) -> bool:
        """
        Check if any uploads failed.

        Returns:
            True if any uploads failed, False otherwise.
        """
        return len(self.failure) != 0

    @staticmethod
    def build_report(
        tpa_base_url: str,
        results: list[tuple[Path, BaseException | str]],
    ) -> "TPAUploadReport":
        """
        Build an upload report from upload results.

        Args:
            results: List of tuples containing file path and either an
                exception (failure) or str (success).

        Returns:
            TPAUploadReport instance with successful and failed uploads categorized.
        """
        # it's quite the hack to use posixpath for url joining, but
        # urllib.parse.urljoin has complex error-prone behaviour which is not
        # needed here
        sboms_url = posixpath.join(tpa_base_url, "sboms")
        success = [
            TPAUploadSuccess(path=path, url=posixpath.join(sboms_url, urn))
            for path, urn in results
            if isinstance(urn, str)
        ]

        failure = []
        for path, result in results:
            if isinstance(result, TPATransientError):
                failure.append(
                    TPAUploadFailure(path=path, message=str(result), transient=True)
                )
            elif isinstance(result, BaseException):
                failure.append(
                    TPAUploadFailure(path=path, message=str(result), transient=False)
                )

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
    retries: int


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
            retries=self.cli_args.retries,
        )
        report = await TPAUploadCommand.upload(config)

        self.exit_code = 1 if report.has_failures() else 0
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
        # pylint: disable=too-many-arguments,too-many-positional-arguments
        sbom_file: Path,
        auth: OIDCClientCredentials | None,
        tpa_url: str,
        semaphore: asyncio.Semaphore,
        labels: dict[str, str],
        retries: int,
    ) -> str:
        """
        Upload a single SBOM file to TPA using HTTP client.

        Args:
            sbom_file: Absolute path to the SBOM file to upload
            auth: Authentication object for the TPA API
            tpa_url: Base URL for the TPA API
            semaphore: A semaphore to limit the number of concurrent uploads
            labels: A mapping of TPA label keys to label values for uploaded SBOMs
            retries: How many retries for SBOM upload will be performed before failing.

        Returns:
            str: URL of the uploaded SBOM
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
                urn = await client.upload_sbom(
                    sbom_file, labels=labels, retries=retries
                )
                LOGGER.info("Successfully uploaded %s to TPA", sbom_file)
                return urn
            except Exception:  # pylint: disable=broad-except
                LOGGER.exception(
                    "Error uploading %s and took %s", filename, time.time() - start_time
                )
                raise

    @staticmethod
    async def upload(
        config: UploadConfig,
    ) -> TPAUploadReport:
        """
        Upload SBOM files to TPA given a directory or a file.

        Args:
            config: Configuration for the command.

        Returns:
            tuple[TPAUploadReport, int]: Upload report and exit code
        """

        LOGGER.info("Found %s SBOMs to upload", len(config.paths))

        semaphore = asyncio.Semaphore(config.workers)

        tasks = [
            TPAUploadCommand.upload_sbom_file(
                sbom_file=sbom_file,
                auth=config.auth,
                tpa_url=config.base_url,
                semaphore=semaphore,
                labels=config.labels,
                retries=config.retries,
            )
            for sbom_file in config.paths
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        LOGGER.info("Upload complete")
        return TPAUploadReport.build_report(
            config.base_url, list(zip(config.paths, results, strict=True))
        )

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
