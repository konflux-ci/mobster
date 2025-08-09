from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.cmd.delete.delete_tpa import TPADeleteCommand
from tests.conftest import setup_mock_tpa_client_with_context_manager


@pytest.mark.asyncio
@patch("mobster.cmd.delete.delete_tpa.get_tpa_default_client")
async def test_execute_delete(
    mock_get_client: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    tpa_env_vars: None,
) -> None:
    """Test delete SBOMs from TPA."""
    setup_mock_tpa_client_with_context_manager(
        mock_get_client, mock_tpa_client_with_http_response
    )

    # Create mock SBOM objects
    sbom1 = MagicMock()
    sbom1.id = "12345"
    sbom1.name = "test/sbom:1.0"

    sbom2 = MagicMock()
    sbom2.id = "67890"
    sbom2.name = "another-sbom"

    # Properly mock the async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom1
        yield sbom2

    list_sboms_mock = MagicMock(side_effect=mock_list_sboms)
    mock_tpa_client_with_http_response.list_sboms = list_sboms_mock
    mock_tpa_client_with_http_response.delete_sbom = AsyncMock()

    args = MagicMock()
    args.dry_run = False
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADeleteCommand(args)

    await command.execute()

    # Verify list_sboms was called with correct parameters
    list_sboms_mock.assert_called_once_with(query="test_query", sort="ingested")

    # Verify delete_sbom was called for each SBOM with normalized names
    expected_calls = [(sbom1.id), (sbom2.id)]

    assert mock_tpa_client_with_http_response.delete_sbom.call_count == 2
    for i, expected_id in enumerate(expected_calls):
        actual_call = mock_tpa_client_with_http_response.delete_sbom.call_args_list[i]
        assert actual_call[0][0] == expected_id

    # Verify the command's success flag is True since all deletions succeeded
    assert command.exit_code == 0


@pytest.mark.asyncio
@patch("mobster.cmd.delete.delete_tpa.get_tpa_default_client")
async def test_execute_delete_dry_run(
    mock_get_client: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    tpa_env_vars: None,
) -> None:
    """Test delete SBOMs from TPA."""
    setup_mock_tpa_client_with_context_manager(
        mock_get_client, mock_tpa_client_with_http_response
    )

    # Create mock SBOM objects
    sbom1 = MagicMock()
    sbom1.id = "12345"
    sbom1.name = "test/sbom:1.0"

    sbom2 = MagicMock()
    sbom2.id = "67890"
    sbom2.name = "another-sbom"

    # Properly mock the async generator for list_sboms
    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom1
        yield sbom2

    list_sboms_mock = MagicMock(side_effect=mock_list_sboms)
    mock_tpa_client_with_http_response.list_sboms = list_sboms_mock
    mock_tpa_client_with_http_response.delete_sbom = AsyncMock()

    args = MagicMock()
    args.dry_run = True
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADeleteCommand(args)

    await command.execute()

    # Verify list_sboms was called with correct parameters
    list_sboms_mock.assert_called_once_with(query="test_query", sort="ingested")

    mock_tpa_client_with_http_response.delete_sbom.assert_not_called()

    # Verify the command's success flag is True since all deletions succeeded
    assert command.exit_code == 0
