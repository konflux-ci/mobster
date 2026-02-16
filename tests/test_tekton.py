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
from mobster.oci.keyless_cosign import KeylessConfig, KeylessCosign
from mobster.release import ReleaseId
from mobster.tekton.common import upload_sboms
from mobster.tekton.component import (
    ProcessComponentArgs,
    parse_args,
    process_component_sboms,
)


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


@patch("mobster.tekton.common.handle_atlas_upload_errors")
@patch("mobster.tekton.common.connect_with_s3")
@pytest.mark.asyncio
async def test_upload_sboms_failure_tries_s3(
    mock_connect_to_s3: MagicMock,
    mock_handle_atlas_upload_errors: AsyncMock,
    upload_config: UploadConfig,
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify that an S3 retry is attempted when upload_to_atlas returns a report
    with upload failures
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
        mock_handle_atlas_upload_errors.assert_awaited()


def test_parse_component_args_static_fail(caplog: pytest.LogCaptureFixture) -> None:
    with pytest.raises(SystemExit):
        parse_args()
        assert "--fulcio-url" not in caplog.text
        assert "--sign-key" in caplog.text


def test_parse_component_args_keyless_fail(
    monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("COSIGN_METHOD", "KEYLESS")
    with pytest.raises(SystemExit):
        parse_args()
        assert "--sign-key" not in caplog.text
        assert "--fulcio-url" in caplog.text


@pytest.mark.asyncio
@patch("mobster.tekton.component.connect_with_s3", MagicMock(return_value=True))
@patch("mobster.tekton.component.upload_snapshot", AsyncMock())
@patch("mobster.tekton.component.tempfile", MagicMock())
@patch("mobster.tekton.component.augment_component_sboms")
async def test_parse_component_args_keyless(
    mock_augment_sboms: AsyncMock, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("COSIGN_METHOD", "KEYLESS")
    relase_id = ReleaseId.new()
    parsed_args = parse_args(
        [
            "--data-dir",
            "foo",
            "--snapshot-spec",
            "bar",
            "--release-id",
            relase_id.id.hex,
            "--result-dir",
            "baz",
            "--rekor-url",
            "https://spam.example",
            "--fulcio-url",
            "a",
            "--oidc-token",
            "/tmp/token",
            "--oidc-issuer-pattern",
            ".*",
            "--oidc-identity-pattern",
            ".*",
            "--atlas-api-url",
            "https://atlas.example",
            "--retry-s3-bucket",
            "bucket_of_lava",
            "--skip-upload",  # do not remove
        ]
    )
    assert parsed_args == ProcessComponentArgs(
        data_dir=Path("foo"),
        snapshot_spec=Path("foo/bar"),
        atlas_api_url="https://atlas.example",
        retry_s3_bucket="bucket_of_lava",
        release_id=relase_id,
        labels={},
        result_dir=Path("foo/baz"),
        atlas_retries=1,
        upload_concurrency=8,
        skip_upload=True,
        skip_s3_upload=False,
        augment_concurrency=8,
        attestation_concurrency=4,
        cosign_config=KeylessConfig(
            fulcio_url="a",
            rekor_url="https://spam.example",
            token_file=Path("/tmp/token"),
            issuer_pattern=".*",
            identity_pattern=".*",
        ),
    )
    await process_component_sboms(parsed_args)
    assert isinstance(mock_augment_sboms.call_args.args[3], KeylessCosign)
