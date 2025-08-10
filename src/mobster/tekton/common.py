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

from mobster.cmd.generate.product import ReleaseData
from mobster.release import ReleaseId, SnapshotModel
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


class AtlasTransientError(Exception):
    """Raised when a transient Atlas error occurs."""


class AtlasUploadError(Exception):
    """Raised when a non-transient Atlas error occurs."""


@dataclass
class CommonArgs:
    """
    Arguments common for both product and component SBOM processing.

    Attributes:
        data_dir: main data directory defined in Tekton task
        snapshot_spec: path to snapshot spec file
        atlas_api_url: url of the TPA instance to use
        retry_s3_bucket: name of the S3 bucket to use for retries
        concurrency: maximum number of concurrent operations
    """

    data_dir: Path
    snapshot_spec: Path
    atlas_api_url: str
    retry_s3_bucket: str
    release_id: ReleaseId
    print_digests: bool
    concurrency: int


def add_common_args(parser: ArgumentParser) -> None:
    """
    Add common command line arguments to the parser.

    Args:
        parser: The argument parser to add arguments to.
    """
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--snapshot-spec", type=Path, required=True)
    parser.add_argument("--atlas-api-url", type=str)
    parser.add_argument("--retry-s3-bucket", type=str)
    parser.add_argument("--release-id", type=ReleaseId, required=True)
    parser.add_argument("--print-digests", action="store_true")
    parser.add_argument("--concurrency", type=int, default="8")


async def upload_sboms(
    dirpath: Path, atlas_url: str, s3_client: S3Client | None, concurrency: int
) -> None:
    """
    Upload SBOMs to Atlas with S3 fallback on transient errors.

    Args:
        dirpath: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.
        s3_client: S3Client object for retry uploads, or None if no retries.

    Raises:
        ValueError: If Atlas authentication credentials are missing or if S3
            client is provided but AWS authentication credentials are missing.
    """
    if not atlas_credentials_exist():
        raise ValueError("Missing Atlas authentication.")

    try:
        LOGGER.info("Starting SBOM upload to Atlas")
        upload_to_atlas(dirpath, atlas_url, concurrency)
    except AtlasTransientError as e:
        if s3_client:
            if not s3_credentials_exist():
                raise ValueError("Missing AWS authentication.") from e
            LOGGER.info("Encountered transient Atlas error, falling back to S3.")
            await upload_to_s3(s3_client, dirpath)


def upload_to_atlas(dirpath: Path, atlas_url: str, concurrency: int) -> None:
    """
    Upload SBOMs to Atlas TPA instance.

    Args:
        dirpath: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.

    Raises:
        AtlasTransientError: If a transient error occurs (exit code 2).
        AtlasUploadError: If a non-transient error occurs.
    """
    try:
        subprocess.run(
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
                "--workers",
                str(concurrency),
            ],
            check=True,
            stdout=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as err:
        if err.returncode == 2:
            raise AtlasTransientError() from err
        raise AtlasUploadError() from err


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


async def upload_to_s3(s3_client: S3Client, dirpath: Path) -> None:
    """
    Upload SBOMs to S3 bucket.

    Args:
        s3_client: S3Client object
        dirpath: Directory containing SBOMs to upload.
    """
    await s3_client.upload_dir(dirpath)


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
