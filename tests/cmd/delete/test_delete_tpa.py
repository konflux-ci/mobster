from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mobster.cmd.delete.delete_tpa import TPADeleteCommand
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
async def test_execute_delete(
    mock_tpa_client_class: MagicMock,
    mock_tpa_client: AsyncMock,
    mock_env_vars: MagicMock,
) -> None:
    """Test delete SBOMs from TPA."""
    mock_tpa_client_class.return_value = mock_tpa_client

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

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock()

    args = MagicMock()
    args.dry_run = False
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADeleteCommand(args)

    await command.execute()

    # Verify list_sboms was called with correct parameters
    mock_tpa_client.list_sboms.assert_called_once_with(
        query="test_query", sort="ingested"
    )

    # Verify delete_sbom was called for each SBOM with normalized names
    expected_calls = [(sbom1.id), (sbom2.id)]

    assert mock_tpa_client.delete_sbom.call_count == 2
    for i, expected_id in enumerate(expected_calls):
        actual_call = mock_tpa_client.delete_sbom.call_args_list[i]
        assert actual_call[0][0] == expected_id

    # Verify the command's success flag is True since all deletions succeeded
    assert command.exit_code == 0


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient")
async def test_execute_delete_dry_run(
    mock_tpa_client_class: MagicMock,
    mock_tpa_client: AsyncMock,
    mock_env_vars: MagicMock,
) -> None:
    """Test delete SBOMs from TPA."""
    mock_tpa_client_class.return_value = mock_tpa_client

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

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock()

    args = MagicMock()
    args.dry_run = True
    args.tpa_base_url = "https://test.tpa.url"
    args.query = "test_query"
    command = TPADeleteCommand(args)

    await command.execute()

    # Verify list_sboms was called with correct parameters
    mock_tpa_client.list_sboms.assert_called_once_with(
        query="test_query", sort="ingested"
    )

    mock_tpa_client.delete_sbom.assert_not_called()

    # Verify the command's success flag is True since all deletions succeeded
    assert command.exit_code == 0
