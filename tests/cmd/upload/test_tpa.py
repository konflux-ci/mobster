from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mobster.cmd.upload.oidc import OIDCClientCredentials
from mobster.cmd.upload.tpa import TPAClient


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
        200, request=httpx.Request("POST", "https://api.example.com/v1/api/v2/sbom")
    )
    mock_post.return_value = mock_response

    client = _get_valid_client()
    response = await client.upload_sbom(sbom_filepath)

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
    with pytest.raises(httpx.HTTPStatusError):
        await client.upload_sbom(sbom_filepath)

    mock_aiofiles_open.assert_called_once_with(sbom_filepath, "rb")
    mock_post.assert_called_once()
