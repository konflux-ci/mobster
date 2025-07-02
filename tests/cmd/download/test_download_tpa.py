from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mobster.cmd.download.download_tpa import TPADownloadCommand
from mobster.cmd.upload.tpa import TPAClient


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for the TPA upload command."""
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "https://test.token.url")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "test-account")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "test-token")


@pytest.fixture
def mock_tpa_client() -> AsyncMock:
    """Create a mock TPA client that returns success for uploads."""
    mock = AsyncMock(spec=TPAClient)
    mock.upload_sbom = AsyncMock(
        return_value=httpx.Response(
            200, request=httpx.Request("POST", "https://example.com")
        )
    )
    return mock


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient")
async def test_execute_download(
    mock_tpa_client_class: MagicMock,
    mock_tpa_client: AsyncMock,
    mock_env_vars: MagicMock,
) -> None:
    """Test downloading SBOMs from TPA."""
    mock_tpa_client_class.return_value = mock_tpa_client

    # Create mock SBOM objects
    sbom1 = MagicMock()
    sbom1.id = "12345"
    sbom1.name = "test/sbom:1.0"  # Name with special characters to test normalization

    sbom2 = MagicMock()
    sbom2.id = "67890"
    sbom2.name = "another-sbom"

    # Properly mock the async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom1
        yield sbom2

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock()

    args = MagicMock()
    args.output = Path("/test/dir")
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADownloadCommand(args)

    await command.execute()

    # Verify list_sboms was called with correct parameters
    mock_tpa_client.list_sboms.assert_called_once_with(
        query="test_query", sort="ingested"
    )

    # Verify download_sbom was called for each SBOM with normalized names
    expected_calls = [
        (
            sbom1.id,
            Path("/test/dir/test_sbom_1.0.json"),
        ),  # Special chars replaced with _
        (sbom2.id, Path("/test/dir/another-sbom.json")),
    ]

    assert mock_tpa_client.download_sbom.call_count == 2
    for i, (expected_id, expected_path) in enumerate(expected_calls):
        actual_call = mock_tpa_client.download_sbom.call_args_list[i]
        assert actual_call[0][0] == expected_id  # First positional arg (sbom_id)
        assert actual_call[0][1] == expected_path  # Second positional arg (path)

    # Verify the command's success flag is True since all downloads succeeded
    assert command.exit_code == 0


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient")
async def test_execute_download_with_download_failure(
    mock_tpa_client_class: MagicMock,
    mock_tpa_client: AsyncMock,
    mock_env_vars: MagicMock,
) -> None:
    """Test downloading SBOMs when download fails."""
    mock_tpa_client_class.return_value = mock_tpa_client

    # Create mock SBOM object
    sbom = MagicMock()
    sbom.id = "12345"
    sbom.name = "test-sbom"

    # Mock the async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock(side_effect=Exception("Download failed"))

    args = MagicMock()
    args.output = Path("/test/dir")
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADownloadCommand(args)

    # The command should raise an exception due to download failure
    with pytest.raises(Exception, match="Download failed"):
        await command.execute()

    # Verify download was attempted
    mock_tpa_client.download_sbom.assert_called_once()

    # Success flag should still be False since execution failed
    assert command.exit_code == 1


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient")
async def test_execute_download_empty_results(
    mock_tpa_client_class: MagicMock,
    mock_tpa_client: AsyncMock,
    mock_env_vars: MagicMock,
) -> None:
    """Test downloading when no SBOMs are found."""
    mock_tpa_client_class.return_value = mock_tpa_client

    # Mock empty async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        return
        yield  # This will never be reached, making it an empty generator

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock()

    args = MagicMock()
    args.output = Path("/test/dir")
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "no_results_query"
    command = TPADownloadCommand(args)

    await command.execute()

    # Verify list_sboms was called
    mock_tpa_client.list_sboms.assert_called_once_with(
        query="no_results_query", sort="ingested"
    )

    # Verify download_sbom was never called since no SBOMs were found
    mock_tpa_client.download_sbom.assert_not_called()

    # Success flag should still be True even with no results
    assert command.exit_code == 0
