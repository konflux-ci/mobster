from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest import MonkeyPatch

from mobster.cmd.upload.upload import (
    TPAUploadFailure,
    TPAUploadReport,
)
from mobster.tekton.common import upload_sboms


@patch("mobster.tekton.common.handle_atlas_transient_errors")
@patch("mobster.tekton.common.connect_with_s3")
@pytest.mark.asyncio
async def test_upload_sboms_transient_failure_tries_s3(
    mock_connect_to_s3: MagicMock,
    mock_handle_atlas_transient_errors: AsyncMock,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify that an S3 retry is attempted when upload_to_atlas returns a report
    with transient failures.
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
        mock_upload.return_value = TPAUploadReport(
            success=[],
            failure=[
                TPAUploadFailure(path=Path("dummy"), message="error", transient=True)
            ],
        )
        await upload_sboms(Path("dir"), "atlas_url", client, concurrency=1, labels={})
        mock_handle_atlas_transient_errors.assert_awaited()


@pytest.mark.asyncio
async def test_upload_sboms_failure(
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify that the upload_to_atlas function fails with a runtime error when
    upload_to_atlas returns a report with non-transient failures.
    """
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "dummy")

    with patch(
        "mobster.tekton.common.upload_to_atlas",
    ) as mock_upload:
        mock_upload.return_value = TPAUploadReport(
            success=[],
            failure=[
                TPAUploadFailure(path=Path("dummy"), message="error", transient=False)
            ],
        )
        with pytest.raises(RuntimeError):
            await upload_sboms(
                Path("dir"), "atlas_url", s3_client=None, concurrency=1, labels={}
            )
