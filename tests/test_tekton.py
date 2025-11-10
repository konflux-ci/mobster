from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest import MonkeyPatch

from mobster.cmd.upload.upload import (
    TPAUploadCommand,
    TPAUploadFailure,
    TPAUploadReport,
    UploadConfig,
)
from mobster.tekton.common import upload_sboms


@pytest.fixture(scope="function")
def upload_config(monkeypatch: MonkeyPatch) -> UploadConfig:
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "dummy")
    auth = TPAUploadCommand.get_oidc_auth()
    return UploadConfig(
        auth=auth,
        base_url="atlas_url",
        workers=1,
        labels={},
        retries=1,
    )


@patch("mobster.tekton.common.handle_atlas_transient_errors")
@patch("mobster.tekton.common.connect_with_s3")
@pytest.mark.asyncio
async def test_upload_sboms_transient_failure_tries_s3(
    mock_connect_to_s3: MagicMock,
    mock_handle_atlas_transient_errors: AsyncMock,
    upload_config: UploadConfig,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify that an S3 retry is attempted when upload_to_atlas returns a report
    with transient failures.
    """
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "dummy")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "dummy")

    client = mock_connect_to_s3.return_value

    with patch(
        "mobster.cmd.upload.upload.TPAUploadCommand.upload",
    ) as mock_upload:
        mock_upload.return_value = TPAUploadReport(
            success=[],
            failure=[
                TPAUploadFailure(path=Path("dummy"), message="error", transient=True)
            ],
        )
        await upload_sboms(
            upload_config,
            client,
            paths=[Path("dir")],
        )
        mock_handle_atlas_transient_errors.assert_awaited()


@pytest.mark.asyncio
async def test_upload_sboms_failure(
    upload_config: UploadConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Verify that the upload_to_atlas function fails with a runtime error when
    upload_to_atlas returns a report with non-transient failures.
    """

    with patch(
        "mobster.cmd.upload.upload.TPAUploadCommand.upload",
    ) as mock_upload:
        mock_upload.return_value = TPAUploadReport(
            success=[],
            failure=[
                TPAUploadFailure(path=Path("dummy"), message="error", transient=False)
            ],
        )
        await upload_sboms(
            upload_config,
            s3_client=None,
            paths=[Path("dir")],
        )
        # WARNING: this change is only temporary. Please see
        # https://issues.redhat.com/browse/ISV-6481
        assert "SBOMs failed to be uploaded to Atlas: " in caplog.messages[-1]
