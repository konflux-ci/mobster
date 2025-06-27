import boto3
import json
import os
import logging
import argparse
from botocore.exceptions import BotoCoreError, ClientError
from mobster.cmd.generate.product import ReleaseData
from mobster.release import Snapshot
from typing import Any

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

    def upload_sboms(self, data: dict, key: str) -> None:
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(data),
                ContentType="application/json"
            )
            LOGGER.info(f"Successfully Stored the SBOM to s3://{self.bucket}/{key}")
        except (BotoCoreError, ClientError) as e:
            LOGGER.error(f"Failed to store SBOM to s3://{self.bucket}/{key}")
            raise
    
def store_sbom_data(
    data: dict,
    uid: str,
    bucket: BucketClient,
    model_class: Any,
    prefix: str,
    log_tag: str
) -> None:
    try:
        validated_data = model_class(**data)
        bucket.upload_sboms(validated_data.dict(), f"{prefix}/{uid}")
    except:
        LOGGER.error(f"[{log_tag}] Failed to store SBOM: {e}")
    
def main() -> None:
    """
    Script entrypoint.
    """
    parser = argparse.ArgumentParser(description="Store SBOM Regeneration data to S3 bucket",)
    parser.add_argument("--type", choices=["snapshots","release-data"], required=True, help="Type of SBOM data")
    parser.add_argument("--input", required=True, help="Path to the JSON input file")
    parser.add_argument("--uid", required=True, help="Tekton Pipeline run UID")
    parser.add_argument("--bucket", required=True, help="The name of the S3 bucket")
    args = parser.parse_args()

    try:
        with open(args.input, "r") as sbom_file:
            sbom_data = json.load(sbom_file)
    except Exception as e:
        LOGGER.error(f"Failed to read input file: {e}")
        raise

    bucket = BucketClient(args.bucket)

    config = {
        "snapshots": (Snapshot, "SNAPSHOT"),
        "release-data": (ReleaseData, "RELEASE_DATA")
    }

    model_class, log_tag = config[args.type]

    store_sbom_data(sbom_data, args.uid, model_class, args.type, log_tag)


if __name__ == "__main__":
    main()

