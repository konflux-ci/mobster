import json
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
import pytest_asyncio

from mobster.cmd.upload.oidc import OIDCClientCredentials
from mobster.cmd.upload.tpa import TPAClient

BASE_URL = "https://api.example.com/v1/"


@pytest_asyncio.fixture
async def tpa_client() -> AsyncGenerator[TPAClient, None]:
    token_url = "https://auth.example.com/oidc/token"
    proxy = "http://proxy.example.com:3128"
    auth = OIDCClientCredentials(
        token_url=token_url, client_id="abc", client_secret="xyz"
    )
    async with TPAClient(BASE_URL, auth, proxy=proxy) as client:
        yield client


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.post")
async def test_upload_sbom_success(
    mock_post: AsyncMock, mock_aiofiles_open: AsyncMock, tpa_client: TPAClient
) -> None:
    sbom_filepath = Path("/path/to/sbom.json")
    file_content = b'{"sbom": "content"}'

    mock_file = AsyncMock()
    mock_file.read.return_value = file_content
    mock_aiofiles_open.return_value.__aenter__.return_value = mock_file

    mock_response = httpx.Response(
        200, request=httpx.Request("POST", "https://api.example.com/v1/api/v2/sbom")
    )
    mock_post.return_value = mock_response

    response = await tpa_client.upload_sbom(sbom_filepath)

    mock_aiofiles_open.assert_called_once_with(sbom_filepath, "rb")
    mock_post.assert_called_once_with(
        "api/v2/sbom",
        content=file_content,
        headers={"content-type": "application/json"},
    )
    assert response == mock_response


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.post")
async def test_upload_sbom_error(
    mock_post: AsyncMock, mock_aiofiles_open: AsyncMock, tpa_client: TPAClient
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

    with pytest.raises(httpx.HTTPStatusError):
        await tpa_client.upload_sbom(sbom_filepath)

    mock_aiofiles_open.assert_called_once_with(sbom_filepath, "rb")
    mock_post.assert_called_once()


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient.get")
async def test_list_sboms(mock_get: AsyncMock, tpa_client: TPAClient) -> None:
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

    response = tpa_client.list_sboms("query", "sort")

    items = [item async for item in response]

    assert len(items) == 2
    assert items[0].id == "1"
    assert items[0].name == "SBOM 1"
    assert items[1].id == "2"
    assert items[1].name == "SBOM 2"


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient.delete")
async def test_delete_sbom(mock_delete: AsyncMock, tpa_client: TPAClient) -> None:
    response = await tpa_client.delete_sbom("123")

    mock_delete.assert_awaited_once_with("api/v2/sbom/123")
    assert response == mock_delete.return_value


@pytest.mark.asyncio
@patch("aiofiles.open")
@patch("mobster.cmd.upload.tpa.TPAClient.stream")
async def test_download_sbom(
    mock_stream: AsyncMock, mock_aiofiles_open: AsyncMock, tpa_client: TPAClient
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

    await tpa_client.download_sbom(sbom_id, local_path)

    mock_stream.assert_called_once_with("GET", f"api/v2/sbom/{sbom_id}/download")

    mock_aiofiles_open.assert_called_once_with(local_path, "wb")

    assert mock_file.write.call_count == 3
    mock_file.write.assert_any_call(b"chunk1")
    mock_file.write.assert_any_call(b"chunk2")
    mock_file.write.assert_any_call(b"chunk3")
