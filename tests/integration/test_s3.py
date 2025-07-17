"""
Integration tests for S3Client.
"""

import json
from pathlib import Path

import pytest

from mobster.cmd.generate.product import ReleaseData, ReleaseNotes
from mobster.release import ComponentModel, SnapshotModel
from mobster.tekton.s3 import S3Client


@pytest.mark.asyncio
async def test_upload_file(s3_client: S3Client, tmp_path: Path) -> None:
    """
    Test uploading a single file to S3.
    """
    test_data = {"test": "data"}
    file_path = tmp_path / "test_file.json"

    with open(file_path, "w") as f:
        json.dump(test_data, f)

    await s3_client.upload_file(file_path)

    assert await s3_client.exists(file_path.name)


@pytest.mark.asyncio
async def test_upload_dir(s3_client: S3Client, tmp_path: Path) -> None:
    """
    Test uploading a directory with multiple files to S3.
    """
    test_files = ["file1.json", "file2.json", "file3.json"]
    for filename in test_files:
        file_path = tmp_path / filename
        with open(file_path, "w") as f:
            json.dump({"file": filename}, f)

    await s3_client.upload_dir(tmp_path)

    for filename in test_files:
        assert await s3_client.exists(filename)


@pytest.mark.parametrize(
    ["data_object", "upload_method", "prefix_attr", "release_id"],
    [
        pytest.param(
            SnapshotModel(
                components=[
                    ComponentModel(
                        name="test-component",
                        repository="quay.io/test/repo",
                        containerImage="quay.io/test/repo@sha256:abc123def456789012345678901234567890123456789012345678901234567890",
                        tags=["v1.0.0", "latest"],
                        **{"rh-registry-repo": "registry.redhat.io/test/repo"},
                    )
                ]
            ),
            "upload_snapshot",
            "snapshot_prefix",
            "test-release-123",
            id="snapshot",
        ),
        pytest.param(
            ReleaseData(
                releaseNotes=ReleaseNotes(
                    product_name="Test Product",
                    product_version="1.0.0",
                    cpe="cpe:/a:redhat:test_product:1.0.0",
                )
            ),
            "upload_release_data",
            "release_data_prefix",
            "test-release-456",
            id="release_data",
        ),
    ],
)
@pytest.mark.asyncio
async def test_upload_data_objects(
    s3_client: S3Client,
    data_object: object,
    upload_method: str,
    prefix_attr: str,
    release_id: str,
) -> None:
    """
    Test uploading data objects (snapshot or release_data) to S3.
    """
    method = getattr(s3_client, upload_method)
    await method(data_object, release_id)

    prefix = getattr(s3_client, prefix_attr)
    expected_key = f"{prefix}/{release_id}"
    assert await s3_client.exists(expected_key)


@pytest.mark.parametrize(
    ["data_type", "data_object", "upload_method", "download_method", "release_id"],
    [
        pytest.param(
            "snapshot",
            SnapshotModel(
                components=[
                    ComponentModel(
                        name="test-component",
                        repository="quay.io/test/repo",
                        containerImage="quay.io/test/repo@sha256:def456abc789012345678901234567890123456789012345678901234567890123",
                        tags=["v2.0.0"],
                        **{"rh-registry-repo": "registry.redhat.io/test/repo"},
                    )
                ]
            ),
            "upload_snapshot",
            "get_snapshot",
            "test-download-snapshot",
            id="snapshot",
        ),
        pytest.param(
            "release_data",
            ReleaseData(
                releaseNotes=ReleaseNotes(
                    product_name="Download Test Product",
                    product_version="2.0.0",
                    cpe="cpe:/a:redhat:download_test:2.0.0",
                )
            ),
            "upload_release_data",
            "get_release_data",
            "test-download-release",
            id="release_data",
        ),
    ],
)
@pytest.mark.asyncio
async def test_get_data_objects(
    s3_client: S3Client,
    tmp_path: Path,
    data_type: str,
    data_object: object,
    upload_method: str,
    download_method: str,
    release_id: str,
) -> None:
    """
    Test downloading data objects (snapshot or release_data) from S3.
    """
    upload_func = getattr(s3_client, upload_method)
    await upload_func(data_object, release_id)

    download_path = tmp_path / f"downloaded_{data_type}.json"

    download_func = getattr(s3_client, download_method)
    result = await download_func(download_path, release_id)

    assert result is True
    assert download_path.exists()


@pytest.mark.parametrize(
    ["data_type", "download_method"],
    [
        pytest.param("snapshot", "get_snapshot", id="snapshot"),
        pytest.param("release_data", "get_release_data", id="release_data"),
    ],
)
@pytest.mark.asyncio
async def test_get_data_objects_nonexistent(
    s3_client: S3Client, tmp_path: Path, data_type: str, download_method: str
) -> None:
    """
    Test downloading non-existent data objects returns False.
    """
    download_path = tmp_path / f"nonexistent_{data_type}.json"

    download_func = getattr(s3_client, download_method)
    result = await download_func(download_path, "nonexistent-release")

    assert result is False
