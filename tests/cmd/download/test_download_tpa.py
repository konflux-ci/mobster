from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.cmd.download.download_tpa import TPADownloadCommand
from tests.conftest import setup_mock_tpa_client_with_context_manager


@pytest.mark.asyncio
@patch("mobster.cmd.download.download_tpa.get_tpa_default_client")
async def test_execute_download(
    mock_get_client: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    tpa_env_vars: None,
) -> None:
    """Test downloading SBOMs from TPA."""
    setup_mock_tpa_client_with_context_manager(
        mock_get_client, mock_tpa_client_with_http_response
    )

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

    mock_tpa_client_with_http_response.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client_with_http_response.download_sbom = AsyncMock()

    args = MagicMock()
    args.output = Path("/test/dir")
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADownloadCommand(args)

    await command.execute()

    # Verify list_sboms was called with correct parameters
    mock_tpa_client_with_http_response.list_sboms.assert_called_once_with(
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

    assert mock_tpa_client_with_http_response.download_sbom.call_count == 2
    for i, (expected_id, expected_path) in enumerate(expected_calls):
        actual_call = mock_tpa_client_with_http_response.download_sbom.call_args_list[i]
        assert actual_call[0][0] == expected_id  # First positional arg (sbom_id)
        assert actual_call[0][1] == expected_path  # Second positional arg (path)

    # Verify the command's success flag is True since all downloads succeeded
    assert command.exit_code == 0


@pytest.mark.asyncio
@patch("mobster.cmd.download.download_tpa.get_tpa_default_client")
async def test_execute_download_with_download_failure(
    mock_get_client: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    tpa_env_vars: None,
) -> None:
    """Test downloading SBOMs when download fails."""
    setup_mock_tpa_client_with_context_manager(
        mock_get_client, mock_tpa_client_with_http_response
    )

    # Create mock SBOM object
    sbom = MagicMock()
    sbom.id = "12345"
    sbom.name = "test-sbom"

    # Mock the async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom

    mock_tpa_client_with_http_response.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client_with_http_response.download_sbom = AsyncMock(
        side_effect=Exception("Download failed")
    )

    args = MagicMock()
    args.output = Path("/test/dir")
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADownloadCommand(args)

    # The command should raise an exception due to download failure
    with pytest.raises(Exception, match="Download failed"):
        await command.execute()

    # Verify download was attempted
    mock_tpa_client_with_http_response.download_sbom.assert_called_once()

    # Success flag should still be False since execution failed
    assert command.exit_code == 1


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient")
async def test_execute_download_empty_results(
    mock_tpa_client_class: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    tpa_env_vars: None,
) -> None:
    """Test downloading when no SBOMs are found."""
    mock_tpa_client_with_http_response.__aenter__ = AsyncMock(
        return_value=mock_tpa_client_with_http_response
    )
    mock_tpa_client_with_http_response.__aexit__ = AsyncMock(return_value=None)
    mock_tpa_client_class.return_value = mock_tpa_client_with_http_response

    # Mock empty async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        return
        yield  # This will never be reached, making it an empty generator

    mock_tpa_client_with_http_response.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client_with_http_response.download_sbom = AsyncMock()

    args = MagicMock()
    args.output = Path("/test/dir")
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "no_results_query"
    command = TPADownloadCommand(args)

    await command.execute()

    # Verify list_sboms was called
    mock_tpa_client_with_http_response.list_sboms.assert_called_once_with(
        query="no_results_query", sort="ingested"
    )

    # Verify download_sbom was never called since no SBOMs were found
    mock_tpa_client_with_http_response.download_sbom.assert_not_called()

    # Success flag should still be True even with no results
    assert command.exit_code == 0
