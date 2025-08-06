from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.cmd.upload.oidc import OIDCClientCredentials
from mobster.cmd.upload.tpa import TPAClient, TPAError, TPATransientError
from mobster.cmd.upload.upload import (
    TPAUploadCommand,
    TPAUploadFailure,
    TPAUploadReport,
    TPAUploadSuccess,
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
    args.labels = {}
    command = TPAUploadCommand(args)

    await command.execute()

    # Verify TPA client was created with correct base URL
    mock_tpa_client_class.assert_called_once_with(
        base_url="https://test.tpa.url", auth=mock_oidc.return_value
    )

    # Verify upload_sbom was called once with the correct file
    mock_tpa_client.upload_sbom.assert_called_once_with(
        Path("/test/single_file.json"), labels={}
    )

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
    assert command.exit_code == 1


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
    assert command.exit_code == 1


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


class TestTPAUploadReport:
    """
    Test class for TPAUploadReport methods.
    """

    def test_get_non_transient_errors_empty(self) -> None:
        """
        Test get_non_transient_errors returns empty list when no failures.
        """
        report = TPAUploadReport(success=[], failure=[])
        result = report.get_non_transient_errors()
        assert result == []

    def test_get_non_transient_errors_only_transient(self) -> None:
        """
        Test get_non_transient_errors returns empty list when only transient failures.
        """
        failures = [
            TPAUploadFailure(
                path=Path("/test/file1.json"),
                transient=True,
                message="Transient error 1",
            ),
            TPAUploadFailure(
                path=Path("/test/file2.json"),
                transient=True,
                message="Transient error 2",
            ),
        ]
        report = TPAUploadReport(success=[], failure=failures)
        result = report.get_non_transient_errors()
        assert result == []

    def test_get_non_transient_errors_only_non_transient(self) -> None:
        """
        Test get_non_transient_errors returns all non-transient failures.
        """
        failures = [
            TPAUploadFailure(
                path=Path("/test/file1.json"),
                transient=False,
                message="Non-transient error 1",
            ),
            TPAUploadFailure(
                path=Path("/test/file2.json"),
                transient=False,
                message="Non-transient error 2",
            ),
        ]
        report = TPAUploadReport(success=[], failure=failures)
        result = report.get_non_transient_errors()

        expected = [
            (Path("/test/file1.json"), "Non-transient error 1"),
            (Path("/test/file2.json"), "Non-transient error 2"),
        ]
        assert result == expected

    def test_get_non_transient_errors_mixed(self) -> None:
        """
        Test get_non_transient_errors returns only non-transient failures when mixed.
        """
        failures = [
            TPAUploadFailure(
                path=Path("/test/file1.json"), transient=True, message="Transient error"
            ),
            TPAUploadFailure(
                path=Path("/test/file2.json"),
                transient=False,
                message="Non-transient error 1",
            ),
            TPAUploadFailure(
                path=Path("/test/file3.json"),
                transient=True,
                message="Another transient error",
            ),
            TPAUploadFailure(
                path=Path("/test/file4.json"),
                transient=False,
                message="Non-transient error 2",
            ),
        ]
        report = TPAUploadReport(success=[], failure=failures)
        result = report.get_non_transient_errors()

        expected = [
            (Path("/test/file2.json"), "Non-transient error 1"),
            (Path("/test/file4.json"), "Non-transient error 2"),
        ]
        assert result == expected

    def test_build_report_all_success(self) -> None:
        """
        Test build_report with all successful uploads.
        """
        results: list[tuple[Path, BaseException | str]] = [
            (Path("/test/file1.json"), "urn:uuid:1234"),
            (Path("/test/file2.json"), "urn:uuid:5678"),
        ]

        expected = TPAUploadReport(
            success=[
                TPAUploadSuccess(
                    path=Path("/test/file1.json"),
                    url="https://tpa.example.com/sboms/urn:uuid:1234",
                ),
                TPAUploadSuccess(
                    path=Path("/test/file2.json"),
                    url="https://tpa.example.com/sboms/urn:uuid:5678",
                ),
            ],
            failure=[],
        )

        report = TPAUploadReport.build_report("https://tpa.example.com", results)
        assert report == expected

    def test_build_report_all_failures(self) -> None:
        """
        Test build_report with all failed uploads.
        """
        results: list[tuple[Path, BaseException | str]] = [
            (Path("/test/file1.json"), TPAError("Regular error")),
            (Path("/test/file2.json"), TPATransientError("Transient error")),
        ]

        expected = TPAUploadReport(
            success=[],
            failure=[
                TPAUploadFailure(
                    path=Path("/test/file1.json"),
                    message="Regular error",
                    transient=False,
                ),
                TPAUploadFailure(
                    path=Path("/test/file2.json"),
                    message="Transient error",
                    transient=True,
                ),
            ],
        )

        report = TPAUploadReport.build_report("https://tpa.example.com", results)
        assert report == expected

    def test_build_report_mixed(self) -> None:
        """
        Test build_report with mixed success and failure results.
        """
        results: list[tuple[Path, BaseException | str]] = [
            (Path("/test/success.json"), "urn:uuid:success"),
            (Path("/test/transient_fail.json"), TPATransientError("Network timeout")),
            (Path("/test/permanent_fail.json"), TPAError("Invalid format")),
        ]

        expected = TPAUploadReport(
            success=[
                TPAUploadSuccess(
                    path=Path("/test/success.json"),
                    url="https://tpa.example.com/sboms/urn:uuid:success",
                ),
            ],
            failure=[
                TPAUploadFailure(
                    path=Path("/test/transient_fail.json"),
                    message="Network timeout",
                    transient=True,
                ),
                TPAUploadFailure(
                    path=Path("/test/permanent_fail.json"),
                    message="Invalid format",
                    transient=False,
                ),
            ],
        )

        report = TPAUploadReport.build_report("https://tpa.example.com", results)
        assert report == expected

    def test_build_report_empty(self) -> None:
        """
        Test build_report with empty results.
        """
        results: list[tuple[Path, BaseException | str]] = []
        expected = TPAUploadReport(success=[], failure=[])

        report = TPAUploadReport.build_report("https://tpa.example.com", results)
        assert report == expected
