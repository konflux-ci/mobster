"""
Common utilities for Tekton tasks.
"""

import asyncio
import hashlib
import logging
import os
import subprocess
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiofiles
from pydantic import ValidationError

from mobster.cmd.generate.product import ReleaseData
from mobster.cmd.upload.upload import TPAUploadReport, UploadExitCode
from mobster.release import ReleaseId, SnapshotModel
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


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
        labels: labels to attach to uploaded SBOMs
    """

    data_dir: Path
    snapshot_spec: Path
    atlas_api_url: str
    retry_s3_bucket: str
    release_id: ReleaseId
    print_digests: bool
    labels: str | None
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
    parser.add_argument("--print-digests", action="store_true")
    parser.add_argument("--labels", type=str, help="Labels to attach to uploaded SBOMs")


async def upload_sboms(
    dirpath: Path,
    atlas_url: str,
    s3_client: S3Client | None,
    concurrency: int,
    labels: str | None = None,
) -> TPAUploadReport:
    """
    Upload SBOMs to Atlas with S3 fallback on transient errors.

    Args:
        dirpath: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.
        s3_client: S3Client object for retry uploads, or None if no retries.
        concurrency: Maximum number of concurrent upload operations.
        labels: Labels to attach to uploaded SBOMs.

    Raises:
        ValueError: If Atlas authentication credentials are missing or if S3
            client is provided but AWS authentication credentials are missing.
    """
    if not atlas_credentials_exist():
        raise ValueError("Missing Atlas authentication.")

    LOGGER.info("Starting SBOM upload to Atlas")
    report = upload_to_atlas(dirpath, atlas_url, concurrency, labels)
    if report.has_failures() and s3_client is not None:
        LOGGER.warning("Encountered transient Atlas error, falling back to S3.")
        await handle_atlas_transient_errors(report, s3_client)
        report.clear_failures()

    return report


async def handle_atlas_transient_errors(
    report: TPAUploadReport, s3_client: S3Client
) -> None:
    """
    Handle Atlas transient errors via the S3 retry mechanism.

    Raises:
        AtlasUploadError: if the retry_s3_bucket is not specified
        ValueError: if S3 credentials aren't specified in env
    """
    if not s3_credentials_exist():
        raise ValueError("Missing AWS authentication while attempting S3 retry.")

    await upload_to_s3(report, s3_client)


def upload_to_atlas(
    dirpath: Path, atlas_url: str, concurrency: int, labels: str | None
) -> TPAUploadReport:
    """
    Upload SBOMs to Atlas TPA instance.

    Args:
        dirpath: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.
        concurrency: Maximum number of concurrent upload operations.
        labels: Labels to attach to uploaded SBOMs.

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
            "--workers",
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


async def upload_to_s3(report: TPAUploadReport, client: S3Client) -> None:
    """ """
    await asyncio.gather(
        *[client.upload_file(failed_sbom) for failed_sbom in report.failure]
    )


def connect_with_s3(retry_s3_bucket: str | None) -> S3Client | None:
    """
    Connect with AWS S3 using S3Client.

    Args:
        retry_s3_bucket: S3 bucket name, or None to skip S3 connection.

    Returns:
        S3Client object if bucket name provided and credentials exist, None otherwise.

    Raises:
        ValueError: If bucket name is provided but AWS credentials are missing.
    """
    if not retry_s3_bucket:
        return None

    if not s3_credentials_exist():
        raise ValueError("Missing AWS authentication.")
    client = S3Client(
        bucket=retry_s3_bucket,
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        endpoint_url=os.environ.get(
            "AWS_ENDPOINT_URL"
        ),  # configurable for testing purposes
    )

    return client


def validate_sbom_input_data(
    sbom_input_file: Path,
    obj: type[SnapshotModel] | type[ReleaseData],
) -> Any:
    """
    Validate SBOM Input data.

    Args:
        sbom_input_file: File path of SBOM input data
        obj: The data model to validate the input data file.

    Returns:
        validated_data: The input data validated by Data Model
    """
    with open(sbom_input_file, encoding="utf-8") as fp:
        validated_data = obj.model_validate_json(fp.read())
    return validated_data


async def upload_snapshot(
    s3_client: S3Client, sbom_input_file: Path, release_id: ReleaseId
) -> None:
    """
    Upload a snapshot to S3 bucket with prefix.

    Args:
        s3_client: S3Client object
        sbom_input_file: File path of SBOM input data
        release_id: The release ID to use as the object key.
    """
    snapshot = validate_sbom_input_data(sbom_input_file, SnapshotModel)
    await s3_client.upload_input_data(snapshot, release_id)


async def upload_release_data(
    s3_client: S3Client, sbom_input_file: Path, release_id: ReleaseId
) -> None:
    """
    Upload release data to S3 bucket with prefix.

    Args:
        s3_client: S3Client object
        sbom_input_file: File path of SBOM input data
        release_id: The release ID to use as the object key.
    """
    release_data = validate_sbom_input_data(sbom_input_file, ReleaseData)
    await s3_client.upload_input_data(release_data, release_id)


async def get_sha256_hexdigest(sbom: Path) -> str:
    """
    Get sha256 digest of specified SBOM.

    Returns:
        str: sha256 digest of the SBOM in hex form
    """
    async with aiofiles.open(sbom, "rb") as fp:
        hash_func = hashlib.sha256()
        while content := await fp.read(8192):
            hash_func.update(content)
        return f"sha256:{hash_func.hexdigest()}"


async def print_digests(paths: list[Path]) -> None:
    """
    Print sha256 hexdigests of SBOMs specified by paths one-per-line to stdout.
    """
    digests = await asyncio.gather(*[get_sha256_hexdigest(path) for path in paths])
    print("\n".join(digests))


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
