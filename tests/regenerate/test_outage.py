"""Unit tests for mobster.regenerate.outage module"""

import datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from mobster.regenerate.base import SbomType
from mobster.regenerate.outage import OutageSbomGenerator, RegenerateOutageArgs
from mobster.release import ReleaseId


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for tests."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")


@pytest.fixture
def outage_args(tmp_path: Path) -> RegenerateOutageArgs:
    """Create a RegenerateOutageArgs instance for testing"""
    since = datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    until = datetime.datetime(2025, 1, 2, 0, 0, 0, tzinfo=datetime.timezone.utc)
    return RegenerateOutageArgs(
        tpa_base_url="https://test.tpa.url",
        tpa_retries=3,
        output_path=tmp_path / "output",
        s3_bucket_url="https://bucket.s3.amazonaws.com",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
        since=since,
        until=until,
    )


def test_outage_sbom_generator_init(
    outage_args: RegenerateOutageArgs, mock_env_vars: None
) -> None:
    """Test OutageSbomGenerator initialization"""
    generator = OutageSbomGenerator(outage_args, SbomType.PRODUCT)

    assert generator.args == outage_args
    assert generator.sbom_type == SbomType.PRODUCT
    assert generator.sbom_release_groups == set()


@pytest.mark.asyncio
async def test_populate_releases(
    outage_args: RegenerateOutageArgs, mock_env_vars: None
) -> None:
    """Test populate_releases fetches release IDs from S3"""
    generator = OutageSbomGenerator(outage_args, SbomType.PRODUCT)
    release_id_1 = ReleaseId.new()
    release_id_2 = ReleaseId.new()

    generator.s3_client = AsyncMock()
    generator.s3_client.get_release_ids_between = AsyncMock(
        return_value=[release_id_1, release_id_2]
    )

    await generator.populate_releases()

    assert release_id_1 in generator.sbom_release_groups
    assert release_id_2 in generator.sbom_release_groups
    generator.s3_client.get_release_ids_between.assert_awaited_once_with(
        since=outage_args.since, until=outage_args.until
    )


@pytest.mark.asyncio
async def test_regenerate_sboms_verbose_logging(
    outage_args: RegenerateOutageArgs,
    mock_env_vars: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test regenerate_sboms logs release groups when verbose"""
    outage_args.verbose = True
    generator = OutageSbomGenerator(outage_args, SbomType.PRODUCT)
    release_id = ReleaseId.new()

    generator.s3_client = AsyncMock()
    generator.s3_client.get_release_ids_between = AsyncMock(return_value=[release_id])
    generator.regenerate_release_groups = AsyncMock()  # type: ignore[method-assign]

    with caplog.at_level("DEBUG"):
        await generator.regenerate_sboms()

    assert "release groups:" in caplog.text
