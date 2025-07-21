import argparse
import json
import logging
import os
import sys
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from mobster.cmd.generate.product import ReleaseData
from mobster.release import SnapshotModel

LOGGER = logging.getLogger(__name__)


class BucketClient:
    """
    Wrapper for S3 operations.
    """

    def __init__(self, bucket: str) -> None:
        self.client = boto3.client(
            "s3",
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        )
        self.bucket = bucket

    def store_sbom_input_data(self, sbom_input_data: dict, key: str) -> None:
        try:

            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(sbom_input_data),
                ContentType="application/json",
            )
            LOGGER.info(
                f"Successfully Stored the SBOM input data to s3://{self.bucket}/{key}"
            )
        except (BotoCoreError, ClientError):
            LOGGER.error(f"Failed to store SBOM input data to s3://{self.bucket}/{key}")
            raise

def entrypoint_for_snapshot_data(
    sbom_input_file: dict,
    release_id: str,
    bucket: BucketClient,
    prefix: str,
    log_tag: str,
) -> None:
    try:
        with open(sbom_input_file, encoding="utf-8") as fp:
            validated_data = SnapshotModel.model_validate_json(fp.read())
        bucket.store_sbom_input_data(validated_data.dict(), f"{prefix}/{release_id}")
    except Exception as e:
        LOGGER.error(f"[{log_tag}]Failed to parse SBOM input data file: {e}")
        raise

def entrypoint_for_release_data(
    sbom_input_file: dict,
    release_id: str,
    bucket: BucketClient,
    prefix: str,
    log_tag: str,
) -> None:
    try:
        with open(sbom_input_file, encoding="utf-8") as fp:
            validated_data = ReleaseData.model_validate_json(fp.read()).release_notes
        bucket.store_sbom_input_data(validated_data.dict(), f"{prefix}/{release_id}")
    except Exception as e:
        LOGGER.error(f"[{log_tag}]Failed to parse SBOM input data file: {e}")
        raise


def main() -> None:
    """
    Script entrypoint.
    """
    parser = argparse.ArgumentParser(
        description="Store SBOM input data to S3 bucket",
    )
    parser.add_argument("--input_file", required=True, help="Path to the JSON input file")
    parser.add_argument("--release_id", required=True, help="Tekton Pipeline run UID")
    parser.add_argument("--bucket", required=True, help="The name of the S3 bucket")
    args = parser.parse_args()

    entrypoint_type = os.path.basename(sys.argv[0])

    bucket = BucketClient(args.bucket)

    if entrypoint_type == "snapshot_spec_data":
        log_tag = "SNAPSHOT"
        entrypoint_for_snapshot_data(
            args.input_file, args.release_id, bucket, SnapshotModel, log_tag
        )

    if entrypoint_type == "release_time_data":
        log_tag = "RELEASE_DATA"
        entrypoint_for_release_data(
            args.input_file, args.release_id, bucket, ReleaseData, log_tag
        )


if __name__ == "__main__":
    main()
