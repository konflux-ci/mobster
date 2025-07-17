"""
Common utilities for Tekton tasks.
"""

import os
import subprocess
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path

from mobster.tekton.s3 import S3Client


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
    """

    data_dir: Path
    snapshot_spec: Path
    atlas_api_url: str
    retry_s3_bucket: str


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


# TODO: this needs further testing to verify that it works as expected
async def upload_sboms(dir: Path, atlas_url: str, retry_s3_bucket: str | None):
    """
    Upload SBOMs to Atlas with S3 fallback on transient errors.

    Args:
        dir: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.
        retry_s3_bucket: S3 bucket name for retry uploads.

    Raises:
        ValueError: If authentication credentials are missing.
    """
    if not atlas_credentials_exist():
        raise ValueError("Missing Atlas authentication.")

    try:
        upload_to_atlas(dir, atlas_url)
    except AtlasTransientError as e:
        if retry_s3_bucket:
            if not s3_credentials_exist():
                raise ValueError("Missing AWS authentication.") from e
            await upload_to_s3(dir, retry_s3_bucket)


def upload_to_atlas(dir: Path, atlas_url: str):
    """
    Upload SBOMs to Atlas TPA instance.

    Args:
        dir: Directory containing SBOMs to upload.
        atlas_url: URL of the Atlas TPA instance.

    Raises:
        AtlasTransientError: If a transient error occurs (exit code 2).
        AtlasUploadError: If a non-transient error occurs.
    """
    res = subprocess.run(
        [
            "mobster",
            "--verbose",
            "upload",
            "tpa",
            "--tpa-base-url",
            atlas_url,
            "--from-dir",
            dir,
            "--report",
        ]
    )
    if res.returncode == 2:
        raise AtlasTransientError()

    if res.returncode != 0:
        raise AtlasUploadError(res.stderr)


async def upload_to_s3(dir: Path, bucket: str):
    """
    Upload SBOMs to S3 bucket.

    Args:
        dir: Directory containing SBOMs to upload.
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

    await client.upload_dir(dir)


def atlas_credentials_exist():
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


def s3_credentials_exist():
    """
    Check if AWS S3 credentials are present in environment.

    Returns:
        bool: True if all required S3 credentials are present.
    """
    return "AWS_ACCESS_KEY_ID" in os.environ and "AWS_SECRET_ACCESS_KEY" in os.environ
