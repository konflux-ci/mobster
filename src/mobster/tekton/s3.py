"""
Async S3 client used for SBOM operations.
"""

import asyncio
from io import BytesIO
from pathlib import Path

import aioboto3
from botocore.exceptions import ClientError

from mobster.cmd.generate.product import ReleaseData
from mobster.release import SnapshotModel


class S3Client:
    """
    Async S3 client used for SBOM operations.
    """

    release_data_prefix = "release-data"
    snapshot_prefix = "snapshots"

    def __init__(
        self,
        bucket: str,
        access_key: str,
        secret_key: str,
        concurrency_limit: int = 10,
        endpoint_url: str | None = None,
    ) -> None:
        """
        Initialize the S3 client.

        Args:
            bucket: Name of the S3 bucket to operate on.
            access_key: AWS access key ID for authentication.
            secret_key: AWS secret access key for authentication.
            endpoint_url: URL of the S3 endpoint.
            concurrency_limit: Maximum number of concurrent uploads (default: 10).
        """
        self.bucket = bucket
        self.session = aioboto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        self.endpoint_url = endpoint_url
        self.semaphore = asyncio.Semaphore(concurrency_limit)

    async def exists(self, key: str) -> bool:
        """
        Check if an object with the given key exists in the bucket.

        Args:
            key: The S3 object key to check for existence.

        Returns:
            True if the object exists, False otherwise.

        Raises:
            ClientError: If an error other than 404 occurs during the check.
        """
        async with self.session.client(
            "s3", endpoint_url=self.endpoint_url
        ) as s3_client:
            try:
                await s3_client.head_object(Bucket=self.bucket, Key=key)
                return True
            except ClientError as e:
                if S3Client._response_is_not_found(e):
                    return False
                raise

    async def upload_dir(self, dir: Path) -> None:
        """
        Upload all files in the specified directory to S3.

        Uses the filename as the S3 object key for each file.

        Args:
            dir: Path to the directory containing files to upload.
        """
        file_paths = [file_path for file_path in dir.iterdir() if file_path.is_file()]

        tasks = [self.upload_file(file_path) for file_path in file_paths]
        await asyncio.gather(*tasks)

    async def upload_file(self, path: Path) -> None:
        """
        Upload a single file to S3.

        Uses the filename as the S3 object key.

        Args:
            path: Path to the file to upload.
        """
        async with self.semaphore:
            key = path.name
            async with self.session.client(
                "s3", endpoint_url=self.endpoint_url
            ) as s3_client:
                await s3_client.upload_file(str(path), self.bucket, key)

    async def upload_snapshot(self, snapshot: SnapshotModel, release_id: str) -> None:
        """
        Upload a snapshot to S3 bucket with prefix.

        Args:
            snapshot: The snapshot model to upload.
            release_id: The release ID to use as the object key.
        """
        await self._upload_input_data(snapshot, release_id)

    async def upload_release_data(self, data: ReleaseData, release_id: str) -> None:
        """
        Upload release data to S3 bucket with prefix.

        Args:
            data: The release data to upload.
            release_id: The release ID to use as the object key.
        """
        await self._upload_input_data(data, release_id)

    async def _upload_input_data(
        self, input: SnapshotModel | ReleaseData, release_id: str
    ) -> None:
        """
        Upload input data (snapshot or release data) to S3 bucket with prefix.

        Args:
            input: The input data to upload (either SnapshotModel or ReleaseData).
            release_id: The release ID to use as part of the object key.
        """
        if isinstance(input, SnapshotModel):
            prefix = self.snapshot_prefix
        else:
            prefix = self.release_data_prefix

        io = BytesIO(input.model_dump_json().encode())
        key = f"{prefix}/{release_id}"
        async with self.session.client(
            "s3", endpoint_url=self.endpoint_url
        ) as s3_client:
            await s3_client.upload_fileobj(io, self.bucket, key)

    async def _get_object(self, path: Path, key: str) -> bool:
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
        async with self.session.client(
            "s3", endpoint_url=self.endpoint_url
        ) as s3_client:
            try:
                await s3_client.download_file(self.bucket, key, str(path))
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
        error = e.response.get("Error")
        if not error:
            return False
        code = error.get("Code")
        if not code:
            return False
        return code == "404"

    async def get_release_data(self, path: Path, release_id: str) -> bool:
        """
        Download release data from S3 to a local file.

        Args:
            path: Local file path where the release data should be saved.
            release_id: The release ID to retrieve.

        Returns:
            True if the release data was successfully downloaded, False if not found.

        Raises:
            ClientError: If an error other than 404 occurs during download.
        """
        key = f"{self.release_data_prefix}/{release_id}"
        return await self._get_object(path, key)

    async def get_snapshot(self, path: Path, release_id: str) -> bool:
        """
        Download snapshot data from S3 to a local file.

        Args:
            path: Local file path where the snapshot data should be saved.
            release_id: The release ID to retrieve.

        Returns:
            True if the snapshot was successfully downloaded, False if not found.

        Raises:
            ClientError: If an error other than 404 occurs during download.
        """
        key = f"{self.snapshot_prefix}/{release_id}"
        return await self._get_object(path, key)

    async def clear_bucket(self) -> None:
        """
        Remove all objects from the S3 bucket.

        This method will delete all objects in the bucket using paginated listing
        to handle buckets with many objects.
        """
        async with self.session.client(
            "s3", endpoint_url=self.endpoint_url
        ) as s3_client:
            paginator = s3_client.get_paginator("list_objects_v2")

            async for page in paginator.paginate(Bucket=self.bucket):
                if "Contents" in page:
                    objects = [{"Key": obj["Key"]} for obj in page["Contents"]]
                    await s3_client.delete_objects(
                        Bucket=self.bucket, Delete={"Objects": objects}
                    )
