"""Unit tests for mobster.regenerate.base module"""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from mobster.error import SBOMError
from mobster.regenerate.base import (
    CommonArgs,
    SBOMRegenerator,
    SBOMType,
)
from mobster.release import ReleaseId
from mobster.tekton.s3 import S3Client


class ConcreteSBOMRegenerator(SBOMRegenerator):
    """Concrete implementation for testing abstract base class"""

    async def populate_releases(self) -> None:
        """Dummy implementation"""
        pass


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for S3 client."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")


@pytest.fixture
def common_args(tmp_path: Path) -> CommonArgs:
    """Create a CommonArgs instance for testing"""
    return CommonArgs(
        tpa_base_url="https://test.tpa.url",
        tpa_retries=3,
        output_path=tmp_path / "output",
        s3_bucket_url="https://bucket.s3.amazonaws.com",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
    )


@pytest.mark.parametrize(
    "s3_bucket_url,expected_bucket,expected_endpoint",
    [
        (
            "https://my-bucket.s3.amazonaws.com",
            "my-bucket",
            "https://s3.amazonaws.com",
        ),
        (
            "https://my-bucket.s3.example.com",
            "my-bucket",
            "https://s3.example.com",
        ),
        (
            "https://example.com/bucket",
            "",
            "https://example.com/bucket",
        ),
        (
            "https://minio:9000/my-bucket",
            "",
            "https://minio:9000/my-bucket",
        ),
    ],
)
def test_parse_s3_bucket_url(
    s3_bucket_url: str, expected_bucket: str, expected_endpoint: str
) -> None:
    """Test parse_s3_bucket_url with various URL formats"""
    bucket, endpoint = SBOMRegenerator.parse_s3_bucket_url(s3_bucket_url)
    assert bucket == expected_bucket
    assert endpoint == expected_endpoint


@pytest.mark.asyncio
async def test_gather_s3_input_data_success(
    common_args: CommonArgs, mock_env_vars: None
) -> None:
    """Test gather_s3_input_data successfully downloads data"""
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    regenerator.s3_client = AsyncMock(spec=S3Client)
    regenerator.s3_client.get_snapshot = AsyncMock(return_value=True)
    regenerator.s3_client.get_release_data = AsyncMock(return_value=True)

    release_id = ReleaseId.new()
    path_snapshot, path_release_data = await regenerator.gather_s3_input_data(
        release_id
    )

    expected_snapshot = (
        common_args.output_path
        / S3Client.snapshot_prefix
        / f"{release_id}.snapshot.json"
    )
    expected_release_data = (
        common_args.output_path
        / S3Client.release_data_prefix
        / f"{release_id}.release_data.json"
    )

    assert path_snapshot == expected_snapshot
    assert path_release_data == expected_release_data
    regenerator.s3_client.get_snapshot.assert_awaited_once_with(
        expected_snapshot, release_id
    )
    regenerator.s3_client.get_release_data.assert_awaited_once_with(
        expected_release_data, release_id
    )


@pytest.mark.asyncio
async def test_gather_s3_input_data_false_return(
    common_args: CommonArgs, mock_env_vars: None, caplog: pytest.LogCaptureFixture
) -> None:
    """
    Test gather_s3_input_data logs warning when
    get_snapshot/get_release_data returns False
    """
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    regenerator.s3_client = AsyncMock(spec=S3Client)

    # Return False to trigger warning log - the loop will continue but eventually exit
    # The loop goes from 1 to max_download_retries (5), so 4 iterations
    regenerator.s3_client.get_snapshot = AsyncMock(return_value=False)
    regenerator.s3_client.get_release_data = AsyncMock(return_value=True)

    release_id = ReleaseId.new()

    # The function will loop and eventually return paths (doesn't raise on False return)
    # But we can verify the warning was logged
    with caplog.at_level("WARNING"):
        path_snapshot, path_release_data = await regenerator.gather_s3_input_data(
            release_id
        )

    # Check that warning was logged
    assert "S3 gather (attempt" in caplog.text
    # Paths are still returned even if False
    assert path_snapshot is not None
    assert path_release_data is not None


@pytest.mark.asyncio
async def test_regenerate_sbom_release_success(
    common_args: CommonArgs, mock_env_vars: None
) -> None:
    """Test regenerate_sbom_release succeeds"""
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    regenerator.gather_s3_input_data = AsyncMock(  # type: ignore[method-assign]
        return_value=(Path("snapshot.json"), Path("release_data.json"))
    )
    regenerator.process_sboms = AsyncMock()  # type: ignore[method-assign]

    release_id = ReleaseId.new()
    result = await regenerator.regenerate_sbom_release(release_id)

    assert result is True
    regenerator.gather_s3_input_data.assert_awaited_once_with(release_id)
    regenerator.process_sboms.assert_awaited_once_with(
        release_id, Path("release_data.json"), Path("snapshot.json")
    )


@pytest.mark.asyncio
async def test_regenerate_sbom_release_fail_fast(
    common_args: CommonArgs, mock_env_vars: None
) -> None:
    """Test regenerate_sbom_release raises error when fail_fast is True"""
    common_args.fail_fast = True
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    regenerator.gather_s3_input_data = AsyncMock(  # type: ignore[method-assign]
        side_effect=SBOMError("Test error")
    )

    release_id = ReleaseId.new()

    with pytest.raises(SBOMError, match="Test error"):
        await regenerator.regenerate_sbom_release(release_id)


@pytest.mark.asyncio
async def test_regenerate_sbom_release_no_fail_fast(
    common_args: CommonArgs, mock_env_vars: None
) -> None:
    """Test regenerate_sbom_release returns False when fail_fast is False"""
    common_args.fail_fast = False
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    regenerator.gather_s3_input_data = AsyncMock(  # type: ignore[method-assign]
        side_effect=SBOMError("Test error")
    )

    release_id = ReleaseId.new()
    result = await regenerator.regenerate_sbom_release(release_id)

    assert result is False


@pytest.mark.asyncio
async def test_regenerate_sbom_release_missing_data(
    common_args: CommonArgs, mock_env_vars: None
) -> None:
    """Test regenerate_sbom_release raises error when data is missing"""
    common_args.fail_fast = True
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    regenerator.gather_s3_input_data = AsyncMock(  # type: ignore[method-assign]
        return_value=(None, Path("release_data.json"))
    )

    release_id = ReleaseId.new()

    with pytest.raises(SBOMError, match="No S3 bucket snapshot"):
        await regenerator.regenerate_sbom_release(release_id)


@pytest.mark.asyncio
async def test_regenerate_release_groups_with_failures(
    common_args: CommonArgs, mock_env_vars: None, caplog: pytest.LogCaptureFixture
) -> None:
    """Test regenerate_release_groups logs failures"""
    common_args.fail_fast = False
    regenerator = ConcreteSBOMRegenerator(common_args, SBOMType.PRODUCT)
    release_id_1 = ReleaseId.new()
    release_id_2 = ReleaseId.new()
    regenerator.sbom_release_groups = {release_id_1, release_id_2}

    # First succeeds, second fails
    regenerator.regenerate_sbom_release = AsyncMock(  # type: ignore[method-assign]
        side_effect=[True, False]
    )

    with caplog.at_level("WARNING"):
        await regenerator.regenerate_release_groups()

    assert "Failed releases:" in caplog.text
