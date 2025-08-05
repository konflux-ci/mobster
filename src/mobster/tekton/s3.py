"""
Async S3 client used for SBOM operations.
"""

import asyncio
from io import BytesIO
from pathlib import Path

import aioboto3
from botocore.exceptions import ClientError

from mobster.cmd.generate.product import ReleaseData
from mobster.release import ReleaseId, SnapshotModel


class S3Client:
    """
    Async S3 client used for SBOM operations.
    """

    release_data_prefix = "release-data"
    snapshot_prefix = "snapshots"

    # pylint: disable=too-many-arguments,too-many-positional-arguments
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

    async def exists(self, key: str, prefix: str | None = None) -> bool:
        """
        Check if an object with the given key exists in the bucket.

        Args:
            key: The S3 object key to check for existence.
            prefix: Optional prefix to prepend to the key.

        Returns:
            True if the object exists, False otherwise.

        Raises:
            ClientError: If an error other than 404 occurs during the check.
        """
        full_key = f"{prefix}/{key}" if prefix else key
        async with self.session.client(
            "s3", endpoint_url=self.endpoint_url
        ) as s3_client:
            try:
                await s3_client.head_object(Bucket=self.bucket, Key=full_key)
                return True
            except ClientError as e:
                if S3Client._response_is_not_found(e):
                    return False
                raise

    async def release_data_exists(self, release_id: ReleaseId) -> bool:
        """
        Check if release data exists for the given release ID.

        Args:
            release_id: The release ID to check for.

        Returns:
            True if the release data exists, False otherwise.

        Raises:
            ClientError: If an error other than 404 occurs during the check.
        """
        return await self.exists(str(release_id), self.release_data_prefix)

    async def snapshot_exists(self, release_id: ReleaseId) -> bool:
        """
        Check if snapshot exists for the given release ID.

        Args:
            release_id: The release ID to check for.

        Returns:
            True if the snapshot exists, False otherwise.

        Raises:
            ClientError: If an error other than 404 occurs during the check.
        """
        return await self.exists(str(release_id), self.snapshot_prefix)

    async def upload_dir(self, dirpath: Path) -> None:
        """
        Upload all files in the specified directory to S3.

        Uses the filename as the S3 object key for each file.

        Args:
            dirpath: Path to the directory containing files to upload.
        """
        file_paths = [
            file_path for file_path in dirpath.iterdir() if file_path.is_file()
        ]

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

    async def upload_input_data(
        self, obj: SnapshotModel | ReleaseData, release_id: ReleaseId
    ) -> None:
        """
        Upload input data (snapshot or release data) to S3 bucket with prefix.

        Args:
            obj: The input data to upload (either SnapshotModel or ReleaseData).
            release_id: The release ID to use as part of the object key.
        """
        if isinstance(obj, SnapshotModel):
            prefix = self.snapshot_prefix
        else:
            prefix = self.release_data_prefix

        io = BytesIO(obj.model_dump_json().encode())
        key = f"{prefix}/{str(release_id)}"
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

    async def get_release_data(self, path: Path, release_id: ReleaseId) -> bool:
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
        key = f"{self.release_data_prefix}/{str(release_id)}"
        return await self._get_object(path, key)

    async def get_snapshot(self, path: Path, release_id: ReleaseId) -> bool:
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
        key = f"{self.snapshot_prefix}/{str(release_id)}"
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

    async def is_prefix_empty(self, prefix: str) -> bool:
        """
        Check if the specified prefix in the S3 bucket is empty.

        Args:
            prefix: The prefix to check. Use "/" to check only root-level objects
                   (objects without any prefix), ignoring objects with prefixes.

        Returns:
            True if the prefix is empty, False otherwise.
        """
        async with self.session.client(
            "s3", endpoint_url=self.endpoint_url
        ) as s3_client:
            if prefix == "/":
                # check only root-level objects (no prefix)
                response = await s3_client.list_objects_v2(
                    Bucket=self.bucket, Delimiter="/"
                )
            else:
                # check specific prefix
                response = await s3_client.list_objects_v2(
                    Bucket=self.bucket, Prefix=prefix
                )
            return "Contents" not in response
