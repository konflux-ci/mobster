from pathlib import Path

import boto3
from botocore.exceptions import ClientError


class S3Client:
    """
    S3 client for checking SBOM uploads in tests.
    """

    def __init__(
        self, bucket: str, access_key: str, secret_key: str, endpoint_url: str
    ) -> None:
        """
        Initialize the S3 client.

        Args:
            bucket: Name of the S3 bucket to operate on.
            access_key: AWS access key ID for authentication.
            secret_key: AWS secret access key for authentication.
            endpoint_url: URL of the S3 endpoint.
        """
        self.bucket = bucket
        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            endpoint_url=endpoint_url,
        )

    def exists(self, key: str) -> bool:
        """
        Returns true if object with {key} exists in the bucket.
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket, Key=key)
            return True
        except ClientError as e:
            if S3Client._response_is_not_found(e):
                return False
            raise

    def _get_object(self, path: Path, key: str) -> bool:
        """
        Download an object from S3 to a local file path.

        Args:
            path: Local file path where the object should be saved.
            key: S3 object key to download.

        Returns:
            True if the object was successfully downloaded, False if not found.

        Raises:
            ClientError: If an error other than 404 occurs during download.
        """
        try:
            self.s3_client.download_file(self.bucket, key, str(path))
        except ClientError as e:
            if S3Client._response_is_not_found(e):
                return False
            raise

        return True

    @staticmethod
    def _response_is_not_found(e: ClientError) -> bool:
        """
        Check if a ClientError represents a 404 Not Found response.

        Args:
            e: The ClientError to check.

        Returns:
            True if the error is a 404 Not Found, False otherwise.
        """
        return e.response["Error"]["Code"] == "404"  # type: ignore

    def get_release_data(self, path: Path, release_id: str) -> bool:
        """
        Saves file at "{self.bucket}/release-data/{release_id}" to path.
        """
        key = f"release-data/{release_id}"
        return self._get_object(path, key)

    def get_snapshot(self, path: Path, release_id: str) -> bool:
        """
        Saves file at "{self.bucket}/snapshots/{release_id}" to path.
        """
        key = f"snapshots/{release_id}"
        return self._get_object(path, key)

    def clear_bucket(self) -> None:
        """
        Removes all objects in the bucket.
        """
        paginator = self.s3_client.get_paginator("list_objects_v2")

        for page in paginator.paginate(Bucket=self.bucket):
            if "Contents" in page:
                objects = [{"Key": obj["Key"]} for obj in page["Contents"]]
                self.s3_client.delete_objects(
                    Bucket=self.bucket, Delete={"Objects": objects}
                )
