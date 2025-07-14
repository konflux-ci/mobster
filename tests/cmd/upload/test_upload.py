from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.cmd.upload.oidc import OIDCClientCredentials, RetryExhaustedException
from mobster.cmd.upload.tpa import TPAClient
from mobster.cmd.upload.upload import (
    TPAUploadCommand,
    TPAUploadReport,
    TPAUploadSuccess,
    UploadExitCode,
)


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
        return_value="urn:uuid:12345678-1234-5678-9012-123456789012"
    )
    return mock


@pytest.fixture
def mock_oidc_credentials() -> MagicMock:
    return MagicMock(spec=OIDCClientCredentials)


@pytest.fixture
def command_args() -> MagicMock:
    args = MagicMock()
    args.tpa_base_url = "https://test.tpa.url"
    args.workers = 2
    return args


@pytest.mark.asyncio
@patch("mobster.cmd.upload.upload.TPAUploadCommand.gather_sboms")
@patch("mobster.cmd.upload.upload.TPAClient")
@patch("mobster.cmd.upload.upload.OIDCClientCredentials")
async def test_execute_upload_from_directory(
    mock_oidc: MagicMock,
    mock_tpa_client_class: MagicMock,
    mock_gather_sboms: MagicMock,
    mock_env_vars: MagicMock,
    mock_tpa_client: MagicMock,
) -> None:
    """Test uploading SBOMs from a directory."""
    mock_tpa_client_class.return_value = mock_tpa_client
    mock_tpa_client.upload_sbom.return_value = (
        "urn:uuid:12345678-1234-5678-9012-123456789012"
    )
    mock_oidc.return_value = MagicMock(spec=OIDCClientCredentials)

    file_list = [Path("/test/dir/file1.json"), Path("/test/dir/file2.json")]
    mock_gather_sboms.return_value = file_list

    args = MagicMock()
    args.from_dir = Path("/test/dir")
    args.file = None
    args.tpa_base_url = "https://test.tpa.url"
    args.workers = 2
    command = TPAUploadCommand(args)

    await command.execute()

    # Verify TPAClient is created with the correct parameters
    for call in mock_tpa_client_class.call_args_list:
        assert call[1]["base_url"] == "https://test.tpa.url"
        assert call[1]["auth"] == mock_oidc.return_value

    # Verify upload_sbom was called for each file
    assert mock_tpa_client.upload_sbom.call_count == len(file_list)

    # Verify the command's exit_code is 0 since all uploads succeeded
    assert command.exit_code == 0


@pytest.mark.asyncio
@patch("mobster.cmd.upload.upload.TPAClient")
@patch("mobster.cmd.upload.upload.OIDCClientCredentials")
async def test_execute_upload_single_file(
    mock_oidc: MagicMock,
    mock_tpa_client_class: MagicMock,
    mock_env_vars: MagicMock,
    mock_tpa_client: MagicMock,
) -> None:
    """Test uploading a single SBOM file."""
    mock_tpa_client_class.return_value = mock_tpa_client
    mock_tpa_client.upload_sbom.return_value = (
        "urn:uuid:12345678-1234-5678-9012-123456789012"
    )
    mock_oidc.return_value = MagicMock(spec=OIDCClientCredentials)

    # Create command with args
    args = MagicMock()
    args.from_dir = None
    args.file = Path("/test/single_file.json")
    args.tpa_base_url = "https://test.tpa.url"
    args.workers = 2
    command = TPAUploadCommand(args)

    await command.execute()

    # Verify TPA client was created with correct base URL
    mock_tpa_client_class.assert_called_once_with(
        base_url="https://test.tpa.url", auth=mock_oidc.return_value
    )

    # Verify upload_sbom was called once with the correct file
    mock_tpa_client.upload_sbom.assert_called_once_with(Path("/test/single_file.json"))

    # Verify the command's exit_code is 0 since upload succeeded
    assert command.exit_code == 0


@pytest.mark.asyncio
@patch("mobster.cmd.upload.upload.TPAUploadCommand.gather_sboms")
@patch("mobster.cmd.upload.upload.TPAClient")
@patch("mobster.cmd.upload.upload.OIDCClientCredentials")
async def test_execute_upload_failure(
    mock_oidc: MagicMock,
    mock_tpa_client_class: MagicMock,
    mock_gather_sboms: MagicMock,
    mock_env_vars: MagicMock,
) -> None:
    mock_tpa_client = AsyncMock(spec=TPAClient)
    # Simulate failure by raising an exception, which will be caught and return False
    mock_tpa_client.upload_sbom = AsyncMock(side_effect=Exception("Upload failed"))
    mock_tpa_client_class.return_value = mock_tpa_client
    mock_oidc.return_value = MagicMock(spec=OIDCClientCredentials)

    file_list = [Path("/test/dir/file1.json"), Path("/test/dir/file2.json")]
    mock_gather_sboms.return_value = file_list

    args = MagicMock()
    args.from_dir = Path("/test/dir")
    args.file = None
    args.tpa_base_url = "https://test.tpa.url"
    args.workers = 1
    command = TPAUploadCommand(args)

    await command.execute()

    # Verify upload_sbom was called for each file
    assert mock_tpa_client.upload_sbom.call_count == len(file_list)

    # Verify the command's exit_code is 1 since all uploads failed
    assert command.exit_code == UploadExitCode.ERROR.value


@pytest.mark.asyncio
@patch("mobster.cmd.upload.upload.TPAUploadCommand.gather_sboms")
@patch("mobster.cmd.upload.upload.TPAClient")
@patch("mobster.cmd.upload.upload.OIDCClientCredentials")
async def test_execute_upload_exception(
    mock_oidc: MagicMock,
    mock_tpa_client_class: MagicMock,
    mock_gather_sboms: MagicMock,
    mock_env_vars: MagicMock,
) -> None:
    mock_tpa_client = AsyncMock(spec=TPAClient)
    mock_tpa_client.upload_sbom = AsyncMock(side_effect=Exception("Upload failed"))
    mock_tpa_client_class.return_value = mock_tpa_client
    mock_oidc.return_value = MagicMock(spec=OIDCClientCredentials)

    file_list = [Path("/test/dir/file1.json")]
    mock_gather_sboms.return_value = file_list

    args = MagicMock()
    args.from_dir = Path("/test/dir")
    args.file = None
    args.tpa_base_url = "https://test.tpa.url"
    args.workers = 1
    command = TPAUploadCommand(args)

    await command.execute()

    mock_tpa_client.upload_sbom.assert_called_once()

    # Verify the command's exit_code is 1 since upload failed
    assert command.exit_code == UploadExitCode.ERROR.value


@pytest.mark.asyncio
@patch("mobster.cmd.upload.upload.TPAUploadCommand.gather_sboms")
@patch("mobster.cmd.upload.upload.TPAClient")
@patch("mobster.cmd.upload.upload.OIDCClientCredentials")
async def test_execute_upload_mixed_results(
    mock_oidc: MagicMock,
    mock_tpa_client_class: MagicMock,
    mock_gather_sboms: MagicMock,
    mock_env_vars: MagicMock,
    capsys: Any,
) -> None:
    mock_tpa_client = AsyncMock(spec=TPAClient)
    # First upload succeeds, second one fails
    mock_tpa_client.upload_sbom.side_effect = [
        "urn:uuid:12345678-1234-5678-9012-123456789012",  # Success returns URN
        Exception("Upload failed"),  # Failure
    ]
    mock_tpa_client_class.return_value = mock_tpa_client
    mock_oidc.return_value = MagicMock(spec=OIDCClientCredentials)

    file_list = [Path("/test/dir/file1.json"), Path("/test/dir/file2.json")]
    mock_gather_sboms.return_value = file_list

    args = MagicMock()
    args.from_dir = Path("/test/dir")
    args.file = None
    args.tpa_base_url = "https://test.tpa.url"
    args.workers = 1
    args.report = True
    command = TPAUploadCommand(args)

    await command.execute()

    expected_report = TPAUploadReport(
        success=[
            TPAUploadSuccess(
                path=Path("/test/dir/file1.json"),
                urn="urn:uuid:12345678-1234-5678-9012-123456789012",
            )
        ],
        failure=[Path("/test/dir/file2.json")],
    )

    out, _ = capsys.readouterr()
    actual_report = TPAUploadReport.model_validate_json(out)
    assert actual_report == expected_report

    # Verify upload_sbom was called for each file
    assert mock_tpa_client.upload_sbom.call_count == len(file_list)

    # Verify the command's exit_code is 1 since at least one upload failed
    assert command.exit_code == UploadExitCode.ERROR.value


def test_gather_sboms(tmp_path: Path) -> None:
    (tmp_path / "file1.json").touch()
    (tmp_path / "file2.json").touch()
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "file3.json").touch()

    result = TPAUploadCommand.gather_sboms(tmp_path)

    assert len(result) == 3

    result_names = {p.name for p in result}
    expected_names = {"file1.json", "file2.json", "file3.json"}
    assert result_names == expected_names


def test_gather_sboms_nonexistent() -> None:
    with pytest.raises(FileNotFoundError):
        TPAUploadCommand.gather_sboms(Path("/nonexistent"))


@pytest.mark.parametrize(
    "results,expected_exit_code,description",
    [
        ([], 0, "empty results list"),
        (["urn:uuid:test", "urn:uuid:test2"], 0, "all successful uploads"),
        (
            [RetryExhaustedException()],
            UploadExitCode.TRANSIENT_ERROR.value,
            "only retry exhausted exceptions",
        ),
        ([ValueError()], UploadExitCode.ERROR.value, "only non-transient exceptions"),
        (
            [RetryExhaustedException(), ValueError()],
            UploadExitCode.ERROR.value,
            "mixed exception types",
        ),
    ],
)
def test_set_exit_code(
    results: list[BaseException | str], expected_exit_code: int, description: str
) -> None:
    """
    Test set_exit_code function with various result combinations.
    """
    command = TPAUploadCommand(MagicMock())
    command.set_exit_code(results)
    assert command.exit_code == expected_exit_code


def test_get_oidc_auth_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test get_oidc_auth() returns None when MOBSTER_TPA_AUTH_DISABLE is true.
    """
    monkeypatch.setenv("MOBSTER_TPA_AUTH_DISABLE", "true")
    assert TPAUploadCommand.get_oidc_auth() is None


def test_get_oidc_auth_enabled_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Test get_oidc_auth() creates OIDCClientCredentials when
    MOBSTER_TPA_AUTH_DISABLE is false.
    """
    monkeypatch.setenv("MOBSTER_TPA_AUTH_DISABLE", "false")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "https://test.token.url")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "test-account")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "test-token")

    result = TPAUploadCommand.get_oidc_auth()
    assert result is not None
    assert result.token_url == "https://test.token.url"
    assert result.client_id == "test-account"
    assert result.client_secret == "test-token"
