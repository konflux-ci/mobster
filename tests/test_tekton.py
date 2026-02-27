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
from mobster.oci.cosign import (
    KeylessSignConfig,
    KeylessVerifyConfig,
    RekorConfig,
    SignConfig,
    StaticSignConfig,
    VerifyConfig,
)
from mobster.oci.cosign.keyless import KeylessSBOMFetcher
from mobster.oci.cosign.static import StaticKeyFetcher
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


@pytest.mark.asyncio
@patch("mobster.tekton.component.connect_with_s3", MagicMock(return_value=True))
@patch("mobster.tekton.component.upload_snapshot", AsyncMock())
@patch("mobster.tekton.component.tempfile", MagicMock())
@patch("mobster.tekton.component.augment_component_sboms")
@patch("mobster.oci.cosign.keyless.check_tuf", MagicMock(return_value=True))
async def test_parse_component_args_keyless(mock_augment_sboms: AsyncMock) -> None:
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
            "--release-data",
            "spam",
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
        cosign_sign_config=SignConfig(
            keyless_config=KeylessSignConfig(
                fulcio_url="a",
                token_file=Path("/tmp/token"),
            ),
            rekor_config=RekorConfig(rekor_url="https://spam.example", rekor_key=None),
        ),
        cosign_verify_config=VerifyConfig(
            keyless_verify_config=KeylessVerifyConfig(
                issuer_pattern=".*",
                identity_pattern=".*",
            ),
            rekor_config=RekorConfig(rekor_url="https://spam.example", rekor_key=None),
        ),
        release_data=Path("foo/spam"),
    )
    await process_component_sboms(parsed_args)
    assert isinstance(mock_augment_sboms.call_args.args[3], KeylessSBOMFetcher)


@pytest.mark.asyncio
@patch("mobster.tekton.component.connect_with_s3", MagicMock(return_value=True))
@patch("mobster.tekton.component.upload_snapshot", AsyncMock())
@patch("mobster.tekton.component.tempfile", MagicMock())
@patch("mobster.tekton.component.augment_component_sboms")
async def test_parse_component_args_static(mock_augment_sboms: AsyncMock) -> None:
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
            "--sign-key",
            "a",
            "--rekor-key",
            "/tmp/public_key",
            "--verify-key",
            "/tmp/public_key_cosign",
            "--atlas-api-url",
            "https://atlas.example",
            "--retry-s3-bucket",
            "bucket_of_powder_snow",
            "--skip-upload",  # do not remove
            "--release-data",
            "spam",
        ]
    )
    assert parsed_args == ProcessComponentArgs(
        data_dir=Path("foo"),
        snapshot_spec=Path("foo/bar"),
        atlas_api_url="https://atlas.example",
        retry_s3_bucket="bucket_of_powder_snow",
        release_id=relase_id,
        labels={},
        result_dir=Path("foo/baz"),
        atlas_retries=1,
        upload_concurrency=8,
        skip_upload=True,
        skip_s3_upload=False,
        augment_concurrency=8,
        attestation_concurrency=4,
        cosign_sign_config=SignConfig(
            rekor_config=RekorConfig(
                rekor_url="https://spam.example", rekor_key=Path("/tmp/public_key")
            ),
            static_sign_config=StaticSignConfig(
                sign_key="a",  # type: ignore
            ),
        ),
        cosign_verify_config=VerifyConfig(
            rekor_config=RekorConfig(
                rekor_url="https://spam.example", rekor_key=Path("/tmp/public_key")
            ),
            static_verify_key="/tmp/public_key_cosign",  # type: ignore
        ),
        release_data=Path("foo/spam"),
    )
    await process_component_sboms(parsed_args)
    assert isinstance(mock_augment_sboms.call_args.args[3], StaticKeyFetcher)
