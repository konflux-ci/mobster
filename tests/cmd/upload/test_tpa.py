import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from mobster.cmd.upload.oidc import OIDCClientCredentials, RetryExhaustedException
from mobster.cmd.upload.tpa import TPAClient, TPAError, TPATransientError


def _get_valid_client() -> TPAClient:
    token_url = "https://auth.example.com/oidc/token"
    proxy = "http://proxy.example.com:3128"
    auth = OIDCClientCredentials(
        token_url=token_url, client_id="abc", client_secret="xyz"
    )
    tpa_client = TPAClient("https://api.example.com/v1/", auth, proxy=proxy)
    return tpa_client


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.post")
async def test_upload_sbom_success(
    mock_post: AsyncMock, mock_aiofiles_open: AsyncMock
) -> None:
    sbom_filepath = Path("/path/to/sbom.json")
    file_content = b'{"sbom": "content"}'

    mock_file = AsyncMock()
    mock_file.read.return_value = file_content
    mock_aiofiles_open.return_value.__aenter__.return_value = mock_file

    mock_response = httpx.Response(
        200,
        request=httpx.Request("POST", "https://api.example.com/v1/api/v2/sbom"),
        content=b'{"id": "urn:uuid:12345678-1234-5678-9012-123456789012"}',
    )
    mock_post.return_value = mock_response

    client = _get_valid_client()
    response = await client.upload_sbom(sbom_filepath)

    mock_aiofiles_open.assert_called_once_with(sbom_filepath, "rb")
    mock_post.assert_called_once_with(
        "api/v2/sbom",
        content=file_content,
        headers={"content-type": "application/json"},
        params={},
    )
    assert response == "urn:uuid:12345678-1234-5678-9012-123456789012"


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.post")
async def test_upload_sbom_error(
    mock_post: AsyncMock, mock_aiofiles_open: AsyncMock
) -> None:
    sbom_filepath = Path("/path/to/sbom.json")
    file_content = b'{"sbom": "content"}'

    mock_file = AsyncMock()
    mock_file.read.return_value = file_content
    mock_aiofiles_open.return_value.__aenter__.return_value = mock_file

    request = httpx.Request("POST", "https://api.example.com/v1/api/v2/sbom")
    error_response = httpx.Response(500, request=request)
    mock_post.side_effect = httpx.HTTPStatusError(
        "Server Error", request=request, response=error_response
    )

    client = _get_valid_client()
    with pytest.raises(TPAError):
        await client.upload_sbom(sbom_filepath)

    mock_aiofiles_open.assert_called_once_with(sbom_filepath, "rb")
    mock_post.assert_called_once()


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.post")
async def test_upload_sbom_retry_exhausted_error(
    mock_post: AsyncMock, mock_aiofiles_open: AsyncMock
) -> None:
    sbom_filepath = Path("/path/to/sbom.json")
    file_content = b'{"sbom": "content"}'

    mock_file = AsyncMock()
    mock_file.read.return_value = file_content
    mock_aiofiles_open.return_value.__aenter__.return_value = mock_file

    mock_post.side_effect = RetryExhaustedException("Retries exhausted")

    client = _get_valid_client()
    with pytest.raises(TPATransientError):
        await client.upload_sbom(sbom_filepath)


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.post")
async def test_upload_sbom_http_error(
    mock_post: AsyncMock, mock_aiofiles_open: AsyncMock
) -> None:
    sbom_filepath = Path("/path/to/sbom.json")
    file_content = b'{"sbom": "content"}'

    mock_file = AsyncMock()
    mock_file.read.return_value = file_content
    mock_aiofiles_open.return_value.__aenter__.return_value = mock_file

    mock_post.side_effect = httpx.HTTPError("Connection failed")

    client = _get_valid_client()
    with pytest.raises(TPAError):
        await client.upload_sbom(sbom_filepath)


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient.get")
async def test_list_sboms(mock_get: AsyncMock) -> None:
    """Test listing SBOMs from TPA API."""
    # Create mock response data that matches the expected model structure
    mock_sbom_data_1 = {
        "id": "1",
        "name": "SBOM 1",
        "ingested": "2023-01-01T00:00:00Z",
        "sha256": "abc123",
        "sha384": "def456",
        "sha512": "ghi789",
        "size": 1024,
        "authors": ["author1"],
        "data_licenses": ["MIT"],
        "number_of_packages": 10,
        "published": "2023-01-01T00:00:00Z",
        "suppliers": ["supplier1"],
    }

    mock_sbom_data_2 = {
        "id": "2",
        "name": "SBOM 2",
        "ingested": "2023-01-02T00:00:00Z",
        "sha256": "xyz789",
        "sha384": "uvw456",
        "sha512": "rst123",
        "size": 2048,
        "authors": ["author2"],
        "data_licenses": ["Apache-2.0"],
        "number_of_packages": 20,
        "published": "2023-01-02T00:00:00Z",
        "suppliers": ["supplier2"],
    }

    page_one = Mock()
    page_one.content = json.dumps(
        {
            "items": [mock_sbom_data_1, mock_sbom_data_2],
            "total": 2,
        }
    ).encode("utf-8")

    page_two = Mock()
    page_two.content = json.dumps({"items": [], "total": 0}).encode("utf-8")

    mock_get.side_effect = [page_one, page_two]

    client = _get_valid_client()
    response = client.list_sboms("query", "sort")

    items = [item async for item in response]

    assert len(items) == 2
    assert items[0].id == "1"
    assert items[0].name == "SBOM 1"
    assert items[1].id == "2"
    assert items[1].name == "SBOM 2"


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient.delete")
async def test_delete_sbom(mock_delete: AsyncMock) -> None:
    client = _get_valid_client()
    response = await client.delete_sbom("123")

    mock_delete.assert_awaited_once_with("api/v2/sbom/123")
    assert response == mock_delete.return_value


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.stream")
async def test_download_sbom(
    mock_stream: AsyncMock, mock_aiofiles_open: AsyncMock
) -> None:
    """Test downloading SBOM from TPA API."""
    sbom_id = "123"
    local_path = Path("/path/to/downloaded_sbom.json")

    async def mock_stream_generator() -> Any:
        for chunk in [b"chunk1", b"chunk2", b"chunk3"]:
            yield chunk

    mock_stream.return_value = mock_stream_generator()

    mock_file = AsyncMock()
    mock_aiofiles_open.return_value.__aenter__.return_value = mock_file

    client = _get_valid_client()
    await client.download_sbom(sbom_id, local_path)

    mock_stream.assert_called_once_with("GET", f"api/v2/sbom/{sbom_id}/download")

    mock_aiofiles_open.assert_called_once_with(local_path, "wb")

    assert mock_file.write.call_count == 3
    mock_file.write.assert_any_call(b"chunk1")
    mock_file.write.assert_any_call(b"chunk2")
    mock_file.write.assert_any_call(b"chunk3")
