"""
Common utilities for Tekton tasks.
"""

import asyncio
import os
import subprocess
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from mobster.cmd.upload.upload import TPAUploadReport, UploadExitCode
from mobster.release import ReleaseId
from mobster.tekton.s3 import S3Client


class AtlasUploadError(Exception):
    """Raised when a non-transient Atlas error occurs."""


@dataclass
class CommonArgs:
    """
    Arguments common for both product and component SBOM processing.

    Attributes:
        data_dir: main data directory defined in Tekton task
        result_dir: path to directory to store results to
        snapshot_spec: path to snapshot spec file
        atlas_api_url: url of the TPA instance to use
        retry_s3_bucket: name of the S3 bucket to use for retries
    """

    data_dir: Path
    snapshot_spec: Path
    atlas_api_url: str
    retry_s3_bucket: str
    release_id: ReleaseId
    result_dir: Path


def add_common_args(parser: ArgumentParser) -> None:
    """
    Add common command line arguments to the parser.

    Args:
        parser: The argument parser to add arguments to.
    """
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--snapshot-spec", type=Path, required=True)
    parser.add_argument("--release-id", type=ReleaseId, required=True)
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--atlas-api-url", type=str)
    parser.add_argument("--retry-s3-bucket", type=str)


async def upload_sboms(
    dirpath: Path, atlas_url: str, retry_s3_bucket: str | None
) -> TPAUploadReport:
    """
    Upload SBOMs to Atlas with S3 fallback on transient errors.

    Args:
        dirpath: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.
        retry_s3_bucket: S3 bucket name for retry uploads.

    Raises:
        ValueError: If Atlas authentication credentials are missing or a retry
            bucket is specified, but the authentication credentials are missing
    """
    if not atlas_credentials_exist():
        raise ValueError("Missing Atlas authentication.")

    report = upload_to_atlas(dirpath, atlas_url)
    if report.has_failures() and retry_s3_bucket is not None:
        await handle_atlas_transient_errors(report, retry_s3_bucket)
        report.clear_failures()

    return report


async def handle_atlas_transient_errors(
    report: TPAUploadReport, retry_s3_bucket: str
) -> None:
    """
    Handle Atlas transient errors via the S3 retry mechanism.

    Raises:
        AtlasUploadError: if the retry_s3_bucket is not specified
        ValueError: if S3 credentials aren't specified in env
    """
    if not s3_credentials_exist():
        raise ValueError("Missing AWS authentication while attempting S3 retry.")

    await upload_to_s3(report, retry_s3_bucket)


def upload_to_atlas(dirpath: Path, atlas_url: str) -> TPAUploadReport:
    """
    Upload SBOMs to Atlas TPA instance.

    Args:
        dirpath: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.

    Raises:
        AtlasUploadError: If a non-transient error occurs.

    Returns:
        TPAUploadReport: Parsed upload report from the upload command.
    """
    result = subprocess.run(
        [
            "mobster",
            "--verbose",
            "upload",
            "tpa",
            "--tpa-base-url",
            atlas_url,
            "--from-dir",
            dirpath,
            "--report",
        ],
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        return TPAUploadReport.model_validate_json(result.stdout)

    if result.returncode == UploadExitCode.TRANSIENT_ERROR.value:
        # special case where all upload errors were only transient we can
        # handle via the S3 retry mechanism
        try:
            return TPAUploadReport.model_validate_json(result.stdout)
        except ValidationError as err:
            raise AtlasUploadError(
                "Atlas upload failed with transient errors and "
                "the report could not be parsed." + result.stderr.decode("utf-8")
            ) from err

    # on all other errors, we signal a failure
    raise AtlasUploadError(result.stderr)


async def upload_to_s3(report: TPAUploadReport, bucket: str) -> None:
    """
    Upload failed SBOMs to S3 bucket for async retry mechanism.

    Args:
        report: TPAUploadReport specifying the failed SBOMs.
        bucket: S3 bucket name.
    """
    client = S3Client(
        bucket=bucket,
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        endpoint_url=os.environ.get(
            "AWS_ENDPOINT_URL"
        ),  # configurable for testing purposes
    )

    await asyncio.gather(
        *[client.upload_file(failed_sbom) for failed_sbom in report.failure]
    )


def atlas_credentials_exist() -> bool:
    """
    Check if Atlas TPA SSO credentials are present in environment.

    Returns:
        bool: True if all required Atlas credentials are present.
    """
    return (
        "MOBSTER_TPA_SSO_ACCOUNT" in os.environ
        and "MOBSTER_TPA_SSO_TOKEN" in os.environ
        and "MOBSTER_TPA_SSO_TOKEN_URL" in os.environ
    )


def s3_credentials_exist() -> bool:
    """
    Check if AWS S3 credentials are present in environment.

    Returns:
        bool: True if all required S3 credentials are present.
    """
    return "AWS_ACCESS_KEY_ID" in os.environ and "AWS_SECRET_ACCESS_KEY" in os.environ
