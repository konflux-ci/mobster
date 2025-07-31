import subprocess
from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest import MonkeyPatch

from mobster.cmd.upload.upload import TPAUploadReport, TPAUploadSuccess, UploadExitCode
from mobster.tekton.common import AtlasUploadError, upload_sboms, upload_to_atlas


@patch("mobster.tekton.common.upload_to_s3")
@patch("mobster.tekton.common.connect_with_s3")
@pytest.mark.asyncio
async def test_upload_sboms_failure_tries_s3(
    mock_connect_to_s3: MagicMock,
    mock_upload_to_s3: AsyncMock,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify that an S3 retry is attempted when upload_to_atlas returns a report
    with failures.
    """
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "dummy")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "dummy")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "dummy")

    client = mock_connect_to_s3.return_value

    with patch(
        "mobster.tekton.common.upload_to_atlas",
    ) as mock_upload:
        mock_upload.return_value = TPAUploadReport(success=[], failure=[Path("dummy")])
        await upload_sboms(Path("dir"), "atlas_url", client, concurrency=1)
        mock_upload_to_s3.assert_called_once()


class TestUploadToAtlas:
    """
    Check that the upload_to_atlas function handles all success and failure
    cases correctly.
    """

    @pytest.fixture
    def mock_process(self) -> MagicMock:
        """
        Create a mock subprocess.CompletedProcess for testing.
        """
        return MagicMock(spec=subprocess.CompletedProcess[bytes])

    @pytest.fixture
    def subprocess_mock(
        self, mock_process: MagicMock
    ) -> Generator[MagicMock, None, None]:
        """
        Patch subprocess.run and return the mock process.
        """
        with patch(
            "mobster.tekton.common.subprocess.run", spec=subprocess.run
        ) as mock_run:
            mock_run.return_value = mock_process
            yield mock_process

    def test_success(self, subprocess_mock: MagicMock) -> None:
        """Test that a succesful upload returns a report."""
        report = TPAUploadReport(
            success=[
                TPAUploadSuccess(path=Path("dummy"), url="https://atlas.net/sboms/urn")
            ],
            failure=[],
        )
        subprocess_mock.returncode = 0
        subprocess_mock.stdout = report.model_dump_json().encode()
        subprocess_mock.stderr = b""

        assert report == upload_to_atlas(Path("dummy"), "https://atlas.net")

    def test_transient_error(self, subprocess_mock: MagicMock) -> None:
        """Test that a transient error returns a report."""
        report = TPAUploadReport(success=[], failure=[Path("dummy")])
        subprocess_mock.returncode = UploadExitCode.TRANSIENT_ERROR.value
        subprocess_mock.stdout = report.model_dump_json().encode()
        subprocess_mock.stderr = b"A transient error."

        assert report == upload_to_atlas(Path("dummy"), "atlas_url")

    @pytest.mark.parametrize(
        "exit_code",
        [
            pytest.param(
                UploadExitCode.TRANSIENT_ERROR.value,
                id="transient_error_with_malformed_report",
            ),
            pytest.param(
                UploadExitCode.ERROR.value,
                id="unexpected_error",
            ),
        ],
    )
    def test_error_conditions(self, subprocess_mock: MagicMock, exit_code: int) -> None:
        """
        Test that various error conditions raise AtlasUploadError as expected.
        """
        subprocess_mock.returncode = exit_code
        subprocess_mock.stdout = b""
        subprocess_mock.stderr = b"Catastrophic failure"

        with pytest.raises(AtlasUploadError):
            upload_to_atlas(Path("dummy"), "atlas_url")
