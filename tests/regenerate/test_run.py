"""Unit tests for mobster.regenerate.run module"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mobster.regenerate.base import SbomType
from mobster.regenerate.by_release_id import (
    RegenerateReleaseArgs,
)
from mobster.regenerate.invalid import RegenerateArgs
from mobster.regenerate.outage import RegenerateOutageArgs
from mobster.regenerate.run import run
from mobster.release import ReleaseId


@pytest.mark.parametrize(
    "sbom_type",
    [SbomType.PRODUCT, SbomType.COMPONENT],
)
@patch("mobster.regenerate.run.asyncio.run")
@patch("mobster.regenerate.run.parse_args")
@patch("mobster.regenerate.run.setup_logging")
def test_run_with_regenerate_args(
    mock_setup_logging: MagicMock,
    mock_parse_args: MagicMock,
    mock_asyncio_run: MagicMock,
    sbom_type: SbomType,
    tmp_path: Path,
) -> None:
    """Test run function with RegenerateArgs"""
    mock_args = RegenerateArgs(
        output_path=tmp_path / "output",
        tpa_base_url="https://tpa.url",
        tpa_retries=3,
        s3_bucket_url="https://s3.url/bucket",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
        mobster_versions="1.2.3,4.5.6",
        tpa_page_size=100,
        ignore_missing_releaseid=False,
    )
    mock_parse_args.return_value = mock_args
    mock_regen_instance = MagicMock()
    mock_regen_instance.regenerate_sboms = MagicMock(return_value=None)

    with patch(
        "mobster.regenerate.run.FaultySbomRegenerator",
        return_value=mock_regen_instance,
    ) as mock_regenerator_cls:
        run(sbom_type)

        mock_setup_logging.assert_called_once_with(verbose=True)
        mock_parse_args.assert_called_once()
        mock_regenerator_cls.assert_called_once_with(mock_args, sbom_type)
        mock_asyncio_run.assert_called_once()


@pytest.mark.parametrize(
    "sbom_type",
    [SbomType.PRODUCT, SbomType.COMPONENT],
)
@patch("mobster.regenerate.run.asyncio.run")
@patch("mobster.regenerate.run.parse_args")
@patch("mobster.regenerate.run.setup_logging")
def test_run_with_outage_args(
    mock_setup_logging: MagicMock,
    mock_parse_args: MagicMock,
    mock_asyncio_run: MagicMock,
    sbom_type: SbomType,
    tmp_path: Path,
) -> None:
    """Test run function with RegenerateOutageArgs"""
    import datetime

    mock_args = RegenerateOutageArgs(
        output_path=tmp_path / "output",
        tpa_base_url="https://tpa.url",
        tpa_retries=3,
        s3_bucket_url="https://s3.url/bucket",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
        since=datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
        until=datetime.datetime(2025, 1, 2, 0, 0, 0, tzinfo=datetime.timezone.utc),
    )
    mock_parse_args.return_value = mock_args
    mock_regen_instance = MagicMock()
    mock_regen_instance.regenerate_sboms = MagicMock(return_value=None)

    with patch(
        "mobster.regenerate.run.OutageSbomGenerator",
        return_value=mock_regen_instance,
    ) as mock_regenerator_cls:
        run(sbom_type)

        mock_setup_logging.assert_called_once_with(verbose=True)
        mock_parse_args.assert_called_once()
        mock_regenerator_cls.assert_called_once_with(mock_args, sbom_type)
        mock_asyncio_run.assert_called_once()


@pytest.mark.parametrize(
    "sbom_type",
    [SbomType.PRODUCT, SbomType.COMPONENT],
)
@patch("mobster.regenerate.run.asyncio.run")
@patch("mobster.regenerate.run.parse_args")
@patch("mobster.regenerate.run.setup_logging")
def test_run_with_release_args(
    mock_setup_logging: MagicMock,
    mock_parse_args: MagicMock,
    mock_asyncio_run: MagicMock,
    sbom_type: SbomType,
    tmp_path: Path,
) -> None:
    """Test run function with RegenerateReleaseArgs"""
    release_ids = [ReleaseId.new(), ReleaseId.new()]
    mock_args = RegenerateReleaseArgs(
        output_path=tmp_path / "output",
        tpa_base_url="https://tpa.url",
        tpa_retries=3,
        s3_bucket_url="https://s3.url/bucket",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
        release_ids=release_ids,
    )
    mock_parse_args.return_value = mock_args
    mock_regen_instance = MagicMock()
    mock_regen_instance.regenerate_sboms = MagicMock(return_value=None)

    with patch(
        "mobster.regenerate.run.ReleaseSbomRegenerator",
        return_value=mock_regen_instance,
    ) as mock_regenerator_cls:
        run(sbom_type)

        mock_setup_logging.assert_called_once_with(verbose=True)
        mock_parse_args.assert_called_once()
        mock_regenerator_cls.assert_called_once_with(mock_args, sbom_type)
        mock_asyncio_run.assert_called_once()


@patch("mobster.regenerate.run.asyncio.run")
@patch("mobster.regenerate.run.parse_args")
@patch("mobster.regenerate.run.setup_logging")
def test_run_with_invalid_args(
    mock_setup_logging: MagicMock,
    mock_parse_args: MagicMock,
    mock_asyncio_run: MagicMock,
) -> None:
    """Test run function raises ValueError for invalid args"""
    mock_parse_args.return_value = "invalid_args"

    with pytest.raises(ValueError, match="Invalid arguments received"):
        run(SbomType.PRODUCT)

    mock_setup_logging.assert_called_once_with(verbose=True)
    mock_parse_args.assert_called_once()
    mock_asyncio_run.assert_not_called()
