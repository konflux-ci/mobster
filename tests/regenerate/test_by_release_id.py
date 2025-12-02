"""Unit tests for mobster.regenerate.by_release_id module"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mobster.regenerate.base import SbomType
from mobster.regenerate.by_release_id import (
    RegenerateReleaseArgs,
    ReleaseSBOMRegenerator,
)
from mobster.release import ReleaseId


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for tests."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")


@pytest.fixture
def release_args(tmp_path: Path) -> RegenerateReleaseArgs:
    """Create a RegenerateReleaseArgs instance for testing"""
    release_ids = [ReleaseId.new(), ReleaseId.new()]
    return RegenerateReleaseArgs(
        tpa_base_url="https://test.tpa.url",
        tpa_retries=3,
        output_path=tmp_path / "output",
        s3_bucket_url="https://bucket.s3.amazonaws.com",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
        release_ids=release_ids,
    )


@pytest.mark.asyncio
async def test_regenerate_sboms_verbose_logging(
    release_args: RegenerateReleaseArgs,
    mock_env_vars: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test regenerate_sboms logs release groups when verbose"""
    release_args.verbose = True
    regenerator = ReleaseSBOMRegenerator(release_args, SbomType.PRODUCT)
    with patch.object(regenerator, "regenerate_release_groups", new_callable=AsyncMock):
        with caplog.at_level("DEBUG"):
            await regenerator.regenerate_sboms()
        assert "release groups:" in caplog.text


@pytest.mark.parametrize(
    "file_content,expected_count",
    [
        # Basic parsing - multiple release IDs
        ("{id1}\n{id2}\n{id3}\n", 3),
        # Quoted release IDs
        ("\"{id1}\"\n'{id2}'\n", 2),
        # Whitespace handling
        ("  {id1}  \n  {id2}\n", 2),
        # Empty file
        ("", 0),
    ],
)
def test_get_releases_from_file(
    tmp_path: Path, file_content: str, expected_count: int
) -> None:
    """Test get_releases_from_file parses release IDs from file with various formats"""
    release_file = tmp_path / "releases.txt"

    # Generate release IDs for this test (only if we need them)
    if expected_count > 0:
        release_ids = [ReleaseId.new() for _ in range(expected_count)]
        # Replace placeholders in file content with actual IDs
        formatted_content = file_content.format(
            **{f"id{i + 1}": release_ids[i].id for i in range(expected_count)}
        )
    else:
        formatted_content = file_content
        release_ids = []

    with open(release_file, "w", encoding="utf-8") as f:
        f.write(formatted_content)

    result = ReleaseSBOMRegenerator.get_releases_from_file(release_file)

    assert len(result) == expected_count

    # Verify IDs match for non-empty cases
    if expected_count > 0:
        for i, expected_id in enumerate(release_ids):
            assert result[i].id == expected_id.id
