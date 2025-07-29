"""
SBOM Input data store operations.
"""

import logging
import os
from pathlib import Path

from mobster.cmd.generate.product import ReleaseData
from mobster.release import SnapshotModel
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


def connect_with_s3(bucket: str) -> S3Client:
    """
    Connect with AWS S3 using S3Client.

    Args:
        bucket: S3 bucket name.

    Returns:
        client: S3Client object
    """
    client = S3Client(
        bucket=bucket,
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        endpoint_url=os.environ.get(
            "AWS_ENDPOINT_URL"
        ),  # configurable for testing purposes
    )

    return client


async def store_sbom_input_data_snapshot_validated(
    sbom_input_file: Path,
    release_id: str,
    bucket: str,
) -> None:
    """
    Store SBOM Input data for snapshot spec to S3 bucket.

    Args:
        sbom_input_file: File path of SBOM input data
        release_id:  The release ID to use as the object key.
        bucket: S3 bucket name.
    """
    try:
        with open(sbom_input_file, encoding="utf-8") as fp:
            validated_data = SnapshotModel.model_validate_json(fp.read())
        client = connect_with_s3(bucket)
        await client.upload_snapshot(validated_data, release_id)
    except Exception as e:
        LOGGER.error("[SNAPSHOT_SPEC] Failed to parse SBOM input data file: %s", e)
        raise


async def store_sbom_input_data_releasedata_validated(
    sbom_input_file: Path,
    release_id: str,
    bucket: str,
) -> None:
    """
    Store SBOM Input data for release_data to S3 bucket.

    Args:
        sbom_input_file: File path of SBOM input data
        release_id:  The release ID to use as the object key.
        bucket: S3 bucket name.
    """
    try:
        with open(sbom_input_file, encoding="utf-8") as fp:
            validated_data = ReleaseData.model_validate_json(fp.read())
        client = connect_with_s3(bucket)
        await client.upload_release_data(validated_data, release_id)
    except Exception as e:
        LOGGER.error("[RELEASE_DATA] Failed to parse SBOM input data file: %s", e)
        raise
