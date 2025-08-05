from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest import MonkeyPatch

from mobster.tekton.common import AtlasTransientError, upload_sboms


@patch("mobster.tekton.common.upload_to_s3")
@patch("mobster.tekton.common.connect_with_s3")
@pytest.mark.asyncio
async def test_upload_sboms_failure_tries_s3(
    mock_connect_to_s3: MagicMock,
    mock_upload_to_s3: AsyncMock,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify that an S3 retry is attempted when upload_to_atlas fails with a
    transient error.
    """
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "dummy")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "dummy")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "dummy")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "dummy")

    client = mock_connect_to_s3.return_value

    with patch(
        "mobster.tekton.common.upload_to_atlas", side_effect=AtlasTransientError
    ):
        await upload_sboms(Path("dir"), "atlas_url", client)
        mock_upload_to_s3.assert_called_once()
