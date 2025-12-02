"""
Integration tests for S3Client.
"""

import asyncio
import datetime
import json
from pathlib import Path

import pytest

from mobster.cmd.generate.product import ReleaseData, ReleaseNotes
from mobster.release import ComponentModel, ReleaseId, SnapshotModel
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

    assert not await s3_client.exists(file_path.name)

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
                        containerImage="quay.io/test/repo@sha256:abc123def456789012345678901234567890123456789012345678901234567890",
                        tags=["v1.0.0", "latest"],
                        **{"rh-registry-repo": "registry.redhat.io/test/repo"},  # type: ignore[arg-type]
                    )
                ]
            ),
            "upload_input_data",
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
            "upload_input_data",
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
                        containerImage="quay.io/test/repo@sha256:def456abc789012345678901234567890123456789012345678901234567890123",
                        tags=["v2.0.0"],
                        **{"rh-registry-repo": "registry.redhat.io/test/repo"},  # type: ignore[arg-type]
                    )
                ]
            ),
            "upload_input_data",
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
            "upload_input_data",
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


@pytest.mark.asyncio
async def test_is_prefix_empty(s3_client: S3Client, tmp_path: Path) -> None:
    """
    Test checking if prefix is empty before and after adding objects.
    """
    # bucket cleared by fixture
    assert await s3_client.is_prefix_empty("/") is True

    test_data = {"test": "data"}
    file_path = tmp_path / "test_file.json"
    with open(file_path, "w") as f:
        json.dump(test_data, f)

    # add object to bucket and check not empty
    await s3_client.upload_file(file_path)
    assert await s3_client.is_prefix_empty("/") is False

    # check that it's empty again after clearing it
    await s3_client.clear_bucket()
    assert await s3_client.is_prefix_empty("/") is True


@pytest.mark.asyncio
async def test_get_release_ids_between(s3_client: S3Client) -> None:
    """
    Test getting ReleaseIds for objects modified between timestamps.

    Creates some objects, waits 10 seconds, creates another object,
    then verifies the method correctly filters by timestamp.
    """
    # Create initial release data objects
    release_id_1 = ReleaseId.new()
    release_id_2 = ReleaseId.new()
    release_id_3 = ReleaseId.new()

    release_data_1 = ReleaseData(
        releaseNotes=ReleaseNotes(
            product_name="Test Product 1",
            product_version="1.0.0",
            cpe="cpe:/a:redhat:test_product_1:1.0.0",
        )
    )
    release_data_2 = ReleaseData(
        releaseNotes=ReleaseNotes(
            product_name="Test Product 2",
            product_version="2.0.0",
            cpe="cpe:/a:redhat:test_product_2:2.0.0",
        )
    )
    release_data_3 = ReleaseData(
        releaseNotes=ReleaseNotes(
            product_name="Test Product 3",
            product_version="3.0.0",
            cpe="cpe:/a:redhat:test_product_3:3.0.0",
        )
    )

    # Record timestamp before first batch
    before_first_batch = datetime.datetime.now(datetime.timezone.utc)

    # Upload first batch of objects
    await s3_client.upload_input_data(release_data_1, release_id_1)
    await s3_client.upload_input_data(release_data_2, release_id_2)
    await s3_client.upload_input_data(release_data_3, release_id_3)

    # Record timestamp after first batch (with small buffer for S3 processing)
    await asyncio.sleep(1)  # Small delay to ensure S3 has processed uploads
    after_first_batch = datetime.datetime.now(datetime.timezone.utc)

    # Wait 10 seconds to ensure timestamp difference
    await asyncio.sleep(5)

    # Create and upload another object after the wait
    release_id_4 = ReleaseId.new()
    release_data_4 = ReleaseData(
        releaseNotes=ReleaseNotes(
            product_name="Test Product 4",
            product_version="4.0.0",
            cpe="cpe:/a:redhat:test_product_4:4.0.0",
        )
    )
    await s3_client.upload_input_data(release_data_4, release_id_4)

    # Record timestamp after second batch (with small buffer for S3 processing)
    await asyncio.sleep(1)  # Small delay to ensure S3 has processed upload
    after_second_batch = datetime.datetime.now(datetime.timezone.utc)

    # Test: Get release IDs from before the wait (should include first 3)
    early_release_ids = await s3_client.get_release_ids_between(
        before_first_batch, after_first_batch
    )
    early_release_id_strs = {str(rid) for rid in early_release_ids}

    # Should include the first 3 release IDs
    assert str(release_id_1) in early_release_id_strs
    assert str(release_id_2) in early_release_id_strs
    assert str(release_id_3) in early_release_id_strs
    # Should NOT include the 4th one (uploaded after the wait)
    assert str(release_id_4) not in early_release_id_strs

    # Test: Get release IDs from after the wait (should include only the 4th one)
    # Use a timestamp slightly after the wait started
    after_wait_start = after_first_batch + datetime.timedelta(seconds=1)
    late_release_ids = await s3_client.get_release_ids_between(
        after_wait_start, after_second_batch
    )
    late_release_id_strs = {str(rid) for rid in late_release_ids}

    # Should include the 4th release ID
    assert str(release_id_4) in late_release_id_strs
    # Should NOT include the first 3 (uploaded before the wait)
    assert str(release_id_1) not in late_release_id_strs
    assert str(release_id_2) not in late_release_id_strs
    assert str(release_id_3) not in late_release_id_strs

    # Test: Get all release IDs (should include all 4)
    all_release_ids = await s3_client.get_release_ids_between(
        before_first_batch, after_second_batch
    )
    all_release_id_strs = {str(rid) for rid in all_release_ids}

    assert str(release_id_1) in all_release_id_strs
    assert str(release_id_2) in all_release_id_strs
    assert str(release_id_3) in all_release_id_strs
    assert str(release_id_4) in all_release_id_strs
    assert len(all_release_id_strs) == 4
