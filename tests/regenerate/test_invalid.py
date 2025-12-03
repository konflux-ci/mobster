"""Unit tests for mobster.regenerate.invalid module"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mobster.cmd.upload.model import SbomSummary
from mobster.regenerate.base import MissingReleaseIdError, SbomType
from mobster.regenerate.invalid import FaultySbomRegenerator, RegenerateArgs
from mobster.release import ReleaseId


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for tests."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")


@pytest.fixture
def regenerate_args(tmp_path: Path) -> RegenerateArgs:
    """Create a RegenerateArgs instance for testing"""
    return RegenerateArgs(
        tpa_base_url="https://test.tpa.url",
        tpa_retries=3,
        output_path=tmp_path / "output",
        s3_bucket_url="https://bucket.s3.amazonaws.com",
        concurrency=5,
        dry_run=False,
        fail_fast=True,
        verbose=False,
        mobster_versions="1.2.3,4.5.6",
        tpa_page_size=100,
        ignore_missing_releaseid=False,
    )


def test_construct_query(regenerate_args: RegenerateArgs, mock_env_vars: None) -> None:
    """Test construct_query creates correct TPA query"""
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)

    query = regenerator.construct_query()

    assert "authors~" in query
    assert "Tool: Mobster-1.2.3" in query
    assert "Tool: Mobster-4.5.6" in query
    assert "|" in query


def test_extract_release_id_from_annotations() -> None:
    """Test extract_release_id extracts from SPDX annotations"""
    release_id = ReleaseId.new()
    sbom_dict = {
        "annotations": [
            {"comment": f"release_id={release_id.id}"},
            {"comment": "other comment"},
        ]
    }

    result = FaultySbomRegenerator.extract_release_id(sbom_dict)

    assert result.id == release_id.id


def test_extract_release_id_from_properties() -> None:
    """Test extract_release_id extracts from CycloneDX properties"""
    release_id = ReleaseId.new()
    sbom_dict = {
        "properties": [
            {"name": "release_id", "value": str(release_id.id)},
            {"name": "other", "value": "value"},
        ]
    }

    result = FaultySbomRegenerator.extract_release_id(sbom_dict)

    assert result.id == release_id.id


def test_extract_release_id_missing() -> None:
    """Test extract_release_id raises MissingReleaseIdError when not found"""
    sbom_dict = {
        "annotations": [{"comment": "no release_id here"}],
        "properties": [{"name": "other", "value": "value"}],
    }

    with pytest.raises(MissingReleaseIdError):
        FaultySbomRegenerator.extract_release_id(sbom_dict)


@pytest.mark.asyncio
async def test_organize_sbom_by_release_id_success(
    regenerate_args: RegenerateArgs, mock_env_vars: None
) -> None:
    """Test organize_sbom_by_release_id adds release_id to groups"""
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)
    release_id = ReleaseId.new()
    sbom = SbomSummary(
        id="test-sbom-id",
        name="test-sbom",
        ingested=datetime.now(),
        sha256="",
        sha384="",
        sha512="",
        size=0,
        authors=[],
        data_licenses=[],
        document_id=None,
        labels={},
        number_of_packages=0,
        published=None,
        suppliers=[],
    )

    regenerator.download_and_extract_release_id = AsyncMock(  # type: ignore[method-assign]
        return_value=release_id
    )

    await regenerator.organize_sbom_by_release_id(sbom)

    assert release_id in regenerator.sbom_release_groups
    regenerator.download_and_extract_release_id.assert_awaited_once_with(sbom)


@pytest.mark.asyncio
async def test_delete_sbom(
    regenerate_args: RegenerateArgs, mock_env_vars: None
) -> None:
    """Test delete_sbom calls TPA client delete"""
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)
    sbom_id = "test-sbom-id"
    mock_response = httpx.Response(
        200, request=httpx.Request("DELETE", "https://example.com")
    )

    with patch("mobster.regenerate.invalid.get_tpa_default_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.delete_sbom = AsyncMock(return_value=mock_response)
        mock_get_client.return_value = mock_client

        result = await regenerator.delete_sbom(sbom_id)

        assert result == mock_response
        mock_client.delete_sbom.assert_awaited_once_with(sbom_id)


@pytest.mark.asyncio
async def test_download_and_extract_release_id_success(
    regenerate_args: RegenerateArgs, mock_env_vars: None, tmp_path: Path
) -> None:
    """
    Test download_and_extract_release_id successfully downloads
    and extracts release_id
    """
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)
    release_id = ReleaseId.new()
    sbom = SbomSummary(
        id="test-sbom-id",
        name="test-sbom",
        ingested=datetime.now(),
        sha256="",
        sha384="",
        sha512="",
        size=0,
        authors=[],
        data_licenses=[],
        document_id=None,
        labels={},
        number_of_packages=0,
        published=None,
        suppliers=[],
    )

    sbom_dict = {"properties": [{"name": "release_id", "value": str(release_id.id)}]}
    sbom_file = tmp_path / "output" / "test-sbom-id.json"
    sbom_file.parent.mkdir(parents=True)
    sbom_file.write_text(json.dumps(sbom_dict))

    with patch("mobster.regenerate.invalid.get_tpa_default_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.download_sbom = AsyncMock()
        mock_get_client.return_value = mock_client

        with patch("mobster.regenerate.invalid.aiofiles.open") as mock_open:
            mock_file = AsyncMock()
            mock_file.read = AsyncMock(return_value=json.dumps(sbom_dict))
            mock_open.return_value.__aenter__ = AsyncMock(return_value=mock_file)
            mock_open.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await regenerator.download_and_extract_release_id(sbom)

            assert result.id == release_id.id
            mock_client.download_sbom.assert_awaited_once()


@pytest.mark.asyncio
async def test_download_and_extract_release_id_retry_on_error(
    regenerate_args: RegenerateArgs, mock_env_vars: None, tmp_path: Path
) -> None:
    """Test download_and_extract_release_id retries on RequestError"""
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)
    release_id = ReleaseId.new()
    sbom = SbomSummary(
        id="test-sbom-id",
        name="test-sbom",
        ingested=datetime.now(),
        sha256="",
        sha384="",
        sha512="",
        size=0,
        authors=[],
        data_licenses=[],
        document_id=None,
        labels={},
        number_of_packages=0,
        published=None,
        suppliers=[],
    )

    sbom_dict = {"properties": [{"name": "release_id", "value": str(release_id.id)}]}
    sbom_file = tmp_path / "output" / "test-sbom-id.json"
    sbom_file.parent.mkdir(parents=True)
    sbom_file.write_text(json.dumps(sbom_dict))

    from httpx import RequestError

    call_count = 0

    async def mock_download(*_: Any, **__: Any) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RequestError("Connection error")
        # Success on retry

    with patch("mobster.regenerate.invalid.get_tpa_default_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.download_sbom = AsyncMock(side_effect=mock_download)
        mock_get_client.return_value = mock_client

        with patch("mobster.regenerate.invalid.aiofiles.open") as mock_open:
            mock_file = AsyncMock()
            mock_file.read = AsyncMock(return_value=json.dumps(sbom_dict))
            mock_open.return_value.__aenter__ = AsyncMock(return_value=mock_file)
            mock_open.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await regenerator.download_and_extract_release_id(sbom)

            assert result.id == release_id.id
            assert call_count == 2  # Should have retried


@pytest.mark.asyncio
async def test_download_and_extract_release_id_file_not_found_retry(
    regenerate_args: RegenerateArgs, mock_env_vars: None, tmp_path: Path
) -> None:
    """Test download_and_extract_release_id retries on FileNotFoundError"""
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)
    release_id = ReleaseId.new()
    sbom = SbomSummary(
        id="test-sbom-id",
        name="test-sbom",
        ingested=datetime.now(),
        sha256="",
        sha384="",
        sha512="",
        size=0,
        authors=[],
        data_licenses=[],
        document_id=None,
        labels={},
        number_of_packages=0,
        published=None,
        suppliers=[],
    )

    sbom_dict = {"properties": [{"name": "release_id", "value": str(release_id.id)}]}

    read_count = 0

    async def mock_read() -> Any:
        nonlocal read_count
        read_count += 1
        if read_count == 1:
            raise FileNotFoundError()
        return json.dumps(sbom_dict)

    with patch("mobster.regenerate.invalid.get_tpa_default_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.download_sbom = AsyncMock()
        mock_get_client.return_value = mock_client

        with patch("mobster.regenerate.invalid.aiofiles.open") as mock_open:
            mock_file = AsyncMock()
            mock_file.read = AsyncMock(side_effect=mock_read)
            mock_open.return_value.__aenter__ = AsyncMock(return_value=mock_file)
            mock_open.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await regenerator.download_and_extract_release_id(sbom)

            assert result.id == release_id.id
            assert read_count == 2  # Should have retried


@pytest.mark.asyncio
async def test_download_and_extract_release_id_missing_release_id(
    regenerate_args: RegenerateArgs, mock_env_vars: None, tmp_path: Path
) -> None:
    """
    Test download_and_extract_release_id raises MissingReleaseIdError
    when not found
    """
    regenerator = FaultySbomRegenerator(regenerate_args, SbomType.PRODUCT)
    sbom = SbomSummary(
        id="test-sbom-id",
        name="test-sbom",
        ingested=datetime.now(),
        sha256="",
        sha384="",
        sha512="",
        size=0,
        authors=[],
        data_licenses=[],
        document_id=None,
        labels={},
        number_of_packages=0,
        published=None,
        suppliers=[],
    )

    sbom_dict = {"properties": [{"name": "other", "value": "value"}]}

    with patch("mobster.regenerate.invalid.get_tpa_default_client") as mock_get_client:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.download_sbom = AsyncMock()
        mock_get_client.return_value = mock_client

        with patch("mobster.regenerate.invalid.aiofiles.open") as mock_open:
            mock_file = AsyncMock()
            mock_file.read = AsyncMock(return_value=json.dumps(sbom_dict))
            mock_open.return_value.__aenter__ = AsyncMock(return_value=mock_file)
            mock_open.return_value.__aexit__ = AsyncMock(return_value=None)

            with pytest.raises(MissingReleaseIdError):
                await regenerator.download_and_extract_release_id(sbom)
