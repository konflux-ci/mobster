"""tests for module for regenerating SBOM documents"""

import asyncio
import json
import logging
import os
from collections.abc import Coroutine
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import mobster.regenerate.base as regen_base
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import TPAClient
from mobster.error import SBOMError
from mobster.regenerate.invalid import FaultySBOMRegenerator, RegenerateArgs
from mobster.release import ReleaseId
from mobster.tekton.s3 import S3Client
from tests.conftest import setup_mock_tpa_client_with_context_manager


def mock_regenerate_args() -> RegenerateArgs:
    """default RegenerateArgs for regenerator tests"""
    return RegenerateArgs(
        output_path=Path("/test/path"),
        tpa_base_url="https://test.ing",
        tpa_retries=20,
        s3_bucket_url="https://test-url",
        concurrency=100,
        dry_run=True,
        fail_fast=True,
        verbose=False,
        mobster_versions="1.2.3,4.5.6",
        tpa_page_size=100,
        ignore_missing_releaseid=True,
    )


def test_regenerate_args() -> None:
    """test arg parsing/setup for regenerator"""
    args = mock_regenerate_args()
    assert args.output_path == Path("/test/path")
    assert args.tpa_base_url == "https://test.ing"
    assert args.s3_bucket_url == "https://test-url"
    assert args.mobster_versions == "1.2.3,4.5.6"
    assert args.concurrency == 100
    assert args.tpa_retries == 20
    assert args.tpa_page_size == 100
    assert args.dry_run is True
    assert args.fail_fast is True
    assert args.verbose is False
    assert args.ignore_missing_releaseid is True


def get_mock_sbom(id: str, name: str) -> SbomSummary:
    """constructs a SbomSummary object for testing"""
    return SbomSummary(
        id=id,
        name=name,
        ingested=datetime.now(),
        sha256="sha256",
        sha384="sha384",
        sha512="sha512",
        size=1,
        authors=[],
        data_licenses=[],
        document_id=None,
        labels={},
        number_of_packages=1,
        published=None,
        suppliers=[],
    )


def mock_download_sbom_json_with_attr(
    id: str, name: str, release_id: str | None, path: Path
) -> str:
    """sample downloaded SBOM data for testing"""
    annotations = [
        {
            "annotationDate": "2025-08-27T06:54:32Z",
            "annotationType": "OTHER",
        }
    ]
    if release_id is not None:
        annotations.append(
            {
                "annotationDate": "2025-08-25T09:34:17Z",
                "annotationType": "OTHER",
                "annotator": "Tool: Mobster-0.6.0",
                "comment": f"release_id={release_id}",
            }
        )

    sbom = {
        "name": f"{name}",
        "documentNamespace": "https://anchore.com/syft/dir/var/workdir/"
        "source-c1dd9b3"
        "9-9573-4d05-8a93-3e712aff5950",
        "creationInfo": {
            "licenseListVersion": "3.25",
            "creators": [
                "Organization: Anchore, Inc",
                "Tool: syft-1.19.0",
                "Tool: Mobster-0.6.0",
            ],
            "created": "2025-08-20T19:15:58Z",
        },
        "packages": [],
        "annotations": annotations,
    }
    return json.dumps(sbom)


def test_gather_s3_input_data(mock_env_vars: None) -> None:
    """tests fetching S3 bucket data"""
    args = mock_regenerate_args()
    sbom_regenerator = FaultySBOMRegenerator(args, regen_base.SbomType.PRODUCT)
    sbom_regenerator.s3_client = AsyncMock(spec=S3Client)
    rid = ReleaseId.new()

    path_snapshot = args.output_path / S3Client.snapshot_prefix / f"{rid}.snapshot.json"
    path_release_data = (
        args.output_path / S3Client.release_data_prefix / f"{rid}.release_data.json"
    )

    async def async_test() -> None:
        result = await sbom_regenerator.gather_s3_input_data(rid)

        assert result == (path_snapshot, path_release_data)
        sbom_regenerator.s3_client.get_snapshot.assert_awaited_once_with(  # type: ignore[attr-defined]
            path_snapshot, rid
        )
        sbom_regenerator.s3_client.get_release_data.assert_awaited_once_with(  # type: ignore[attr-defined]
            path_release_data, rid
        )

    asyncio.run(async_test())


@pytest.fixture
def dummy_args(tmp_path: Path) -> list[str]:
    """Fixture to simulate command line arguments."""
    return [
        "--output-dir",
        str(tmp_path / "output"),
        "--tpa-base-url",
        "https://tpa.url",
        "--s3-bucket-url",
        "https://s3.url/bucket",
        "--concurrency",
        "500",
        "--tpa-retries",
        "300",
        "--tpa-page-size",
        "1500",
        "--dry-run",
        "--non-fail-fast",
        "--verbose",
        "invalid",  # command subcommand (must come after common args)
        "--mobster-versions",
        "0.1.2,3.4.5",
        "--ignore-missing-releaseid",
    ]


def test_parse_args(
    tmp_path: Path,
    dummy_args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the parse_args function for proper argument parsing."""
    monkeypatch.setattr("sys.argv", ["program_name"] + dummy_args)
    from mobster.regenerate.cli import parse_args

    args = parse_args()
    assert isinstance(args, RegenerateArgs)
    assert args.output_path == Path(tmp_path / "output")
    assert args.tpa_base_url == "https://tpa.url"
    assert args.s3_bucket_url == "https://s3.url/bucket"
    assert args.mobster_versions == "0.1.2,3.4.5"
    assert args.concurrency == 500
    assert args.tpa_retries == 300
    assert args.tpa_page_size == 1500
    assert args.dry_run is True
    assert args.fail_fast is False
    assert args.ignore_missing_releaseid is True
    assert args.verbose is True


@pytest.mark.asyncio
async def test_organize_sbom_by_release_id(
    mock_env_vars: None, mock_tpa_client: AsyncMock
) -> None:
    mock_args = mock_regenerate_args()
    sbom1 = get_mock_sbom(id="a", name="sbom_1")
    mock_release_id = MagicMock(ReleaseId)

    sbom_regenerator = FaultySBOMRegenerator(mock_args, regen_base.SbomType.PRODUCT)
    sbom_regenerator.download_and_extract_release_id = AsyncMock(  # type: ignore[method-assign]
        return_value=mock_release_id
    )

    await sbom_regenerator.organize_sbom_by_release_id(sbom1)

    sbom_regenerator.download_and_extract_release_id.assert_called_with(sbom1)


def test_prepare_output_paths(tmp_path: Path) -> None:
    """verify prepare_output_paths ensures the required dirs exist"""
    test_output_path = tmp_path / "output"
    from mobster.regenerate.cli import prepare_output_paths

    prepare_output_paths(str(test_output_path))
    assert (test_output_path / "release-data").exists()
    assert (test_output_path / "snapshots").exists()


def test_prepare_output_paths_with_existing_path(tmp_path: Path) -> None:
    """verify prepare_output_paths ensures the required dirs exist"""
    output_path = tmp_path / "output"
    (output_path / S3Client.release_data_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / S3Client.snapshot_prefix).mkdir(parents=True, exist_ok=True)

    from mobster.regenerate.cli import prepare_output_paths

    prepare_output_paths(str(output_path))

    release_data_dir = output_path / S3Client.release_data_prefix
    snapshot_dir = output_path / S3Client.snapshot_prefix

    assert release_data_dir.is_dir()
    assert snapshot_dir.is_dir()
    assert os.path.exists(release_data_dir)
    assert os.path.exists(snapshot_dir)


def test_prepare_output_paths_with_nonexisting_path(tmp_path: Path) -> None:
    """verify prepare_output_paths ensures the required dirs exist"""
    output_path = tmp_path / "foobar12345"
    from mobster.regenerate.cli import prepare_output_paths

    prepare_output_paths(str(output_path))

    release_data_dir = output_path / S3Client.release_data_prefix
    snapshot_dir = output_path / S3Client.snapshot_prefix

    assert output_path.is_dir()
    assert release_data_dir.is_dir()
    assert snapshot_dir.is_dir()


def test_extract_release_id_with_annotations() -> None:
    """verify extract_release_id handles annotations"""
    expected_release_id = ReleaseId.new()
    sbom_dict = {
        "annotations": [
            {"comment": f"release_id={expected_release_id.id}"},
        ]
    }
    result = FaultySBOMRegenerator.extract_release_id(sbom_dict)
    assert expected_release_id.id == result.id


def test_extract_release_id_with_properties() -> None:
    """verify extract_release_id handles properties"""
    expected_release_id = ReleaseId.new()
    sbom_dict = {
        "properties": [
            {"name": "release_id", "value": f"{expected_release_id.id}"},
        ]
    }
    result = FaultySBOMRegenerator.extract_release_id(sbom_dict)
    assert expected_release_id.id == result.id


def sbom_from_dict(sbom_dict: dict[str, Any]) -> SbomSummary:
    """convenience test function to unmarshal SBOMSummary from dict"""
    return json.loads(json.dumps(sbom_dict))  # type: ignore[no-any-return]


def test_extract_release_id_missing() -> None:
    """verify extract_release_id handles missing ReleaseId"""
    sbom_dict = {
        "annotations": [
            {"comment": "etc"},
        ],
        "properties": [
            {"name": "foo", "value": "bar"},
        ],
    }
    try:
        FaultySBOMRegenerator.extract_release_id(sbom_dict)
        # shouldn't get here, so fail
        raise AssertionError()
    except regen_base.MissingReleaseIdError:
        # expected
        assert True


@pytest.fixture
def sbom_regenerator(mock_env_vars: None) -> FaultySBOMRegenerator:
    """Fixture to provide a SbomRegenerator instance."""
    args = mock_regenerate_args()
    args.dry_run = False
    return FaultySBOMRegenerator(args=args, sbom_type=regen_base.SbomType.PRODUCT)


@pytest.mark.asyncio
async def test_regenerate_sbom_release(sbom_regenerator: Any, caplog: Any) -> None:
    """Test regenerate_sbom_release"""
    with (
        patch(
            "mobster.regenerate.base.SbomRegenerator.gather_s3_input_data",
            new_callable=AsyncMock,
        ) as mock_gather_s3_input_data,
        patch(
            "mobster.regenerate.base.SbomRegenerator.process_sboms",
            new_callable=AsyncMock,
        ) as mock_process_sboms,
    ):
        mock_gather_s3_input_data.return_value = (
            Path("snapshot.json"),
            Path("release_data.json"),
        )

        release_id = ReleaseId.new()
        sbom_regenerator.sbom_release_groups = {release_id}

        sbom_regenerator.args.dry_run = False

        with caplog.at_level("DEBUG"):
            result = await sbom_regenerator.regenerate_sbom_release(release_id)

            assert result is True
            assert mock_gather_s3_input_data.called
            assert mock_process_sboms.called
            assert f"Generate SBOM release: {str(release_id)}" in caplog.text


async def async_test_wrapper(the_coro: Coroutine[Any, Any, Any]) -> Any:
    """convenience test wrapper for coroutine"""
    return await the_coro


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for the TPA upload command."""
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "https://test.token.url")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "test-account")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "test-token")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")


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
@patch("mobster.regenerate.invalid.get_tpa_default_client")
async def test_regenerate_sboms_success(
    mock_get_client: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    mock_env_vars: None,
    caplog: Any,
) -> None:
    setup_mock_tpa_client_with_context_manager(
        mock_get_client, mock_tpa_client_with_http_response
    )
    sbom_summary_1 = get_mock_sbom("1", "A")
    sbom_download_1 = mock_download_sbom_json_with_attr(
        "1", "A", "9e3efbfb-565d-46ef-96b7-8e2bbe0472a1", Path("/tmp/foo")
    )

    async def mock_list_sboms(query: str, sort: str, page_size: int) -> Any:
        yield sbom_summary_1

    async def mock_download_sbom(sbom_id: str, path: Path) -> Any:
        yield sbom_download_1

    list_sboms_mock = MagicMock(side_effect=mock_list_sboms)
    mock_tpa_client_with_http_response.list_sboms = list_sboms_mock

    download_sbom_mock = MagicMock(side_effect=mock_download_sbom)
    mock_tpa_client_with_http_response.download_sbom = download_sbom_mock

    args = mock_regenerate_args()
    sbom_type = regen_base.SbomType.PRODUCT
    sbom_regenerator = FaultySBOMRegenerator(args=args, sbom_type=sbom_type)

    with (
        patch(
            "mobster.regenerate.invalid.FaultySBOMRegenerator.construct_query",
            return_value="test_query",
        ) as mock_construct_query,
        patch(
            "mobster.regenerate.invalid.FaultySBOMRegenerator.organize_sbom_by_release_id",
            new_callable=AsyncMock,
        ) as mock_organize_sbom_by_release_id,
        patch(
            "mobster.regenerate.base.SbomRegenerator.regenerate_release_groups",
            new_callable=AsyncMock,
        ) as mock_regenerate_release_groups,
    ):
        sbom_regenerator.args.fail_fast = False
        sbom_regenerator.args.verbose = True
        caplog_level = logging.DEBUG

        with caplog.at_level(caplog_level):
            await sbom_regenerator.regenerate_sboms()

            assert "release groups: " in caplog.text
            assert mock_construct_query.called
            assert mock_organize_sbom_by_release_id.call_count == 1
            assert mock_regenerate_release_groups.called
            assert mock_regenerate_release_groups.call_count == 1


@pytest.mark.asyncio
@patch("mobster.regenerate.invalid.get_tpa_default_client")
async def test_regenerate_sboms_error(
    mock_get_client: MagicMock,
    mock_tpa_client_with_http_response: AsyncMock,
    mock_env_vars: None,
    caplog: Any,
) -> None:
    setup_mock_tpa_client_with_context_manager(
        mock_get_client, mock_tpa_client_with_http_response
    )
    dummy_release_id = "9e3efbfb-565d-46ef-96b7-8e2bbe0472a1"
    sbom_summary_1 = get_mock_sbom("1", "A")
    sbom_download_1 = mock_download_sbom_json_with_attr(
        "1", "A", dummy_release_id, Path("/tmp/foo")
    )

    async def mock_list_sboms(query: str, sort: str, page_size: int) -> Any:
        yield sbom_summary_1

    async def mock_download_sbom(sbom_id: str, path: Path) -> Any:
        yield sbom_download_1

    list_sboms_mock = MagicMock(side_effect=mock_list_sboms)
    mock_tpa_client_with_http_response.list_sboms = list_sboms_mock

    download_sbom_mock = MagicMock(side_effect=mock_download_sbom)
    mock_tpa_client_with_http_response.download_sbom = download_sbom_mock

    args = mock_regenerate_args()
    sbom_type = regen_base.SbomType.PRODUCT
    sbom_regenerator = FaultySBOMRegenerator(args=args, sbom_type=sbom_type)

    with (
        patch(
            "mobster.regenerate.invalid.FaultySBOMRegenerator.construct_query",
            return_value="test_query",
        ),
        patch(
            "mobster.regenerate.invalid.FaultySBOMRegenerator.organize_sbom_by_release_id",
            new_callable=AsyncMock,
        ) as mock_organize_sbom_by_release_id,
    ):
        mock_organize_sbom_by_release_id.side_effect = SBOMError("Missing ReleaseId")

        caplog_level = logging.DEBUG
        sbom_regenerator.args.verbose = True
        for fail_fast in [True, False]:
            sbom_regenerator.args.fail_fast = fail_fast
            with caplog.at_level(caplog_level):
                try:
                    await sbom_regenerator.regenerate_sboms()
                    if fail_fast:
                        raise AssertionError("expected: error")
                    assert "release groups: " in caplog.text
                except SystemExit as e:
                    assert "Missing ReleaseId" in caplog.text
                    assert type(e).__name__ == SystemExit.__name__

    with (
        patch(
            "mobster.regenerate.invalid.FaultySBOMRegenerator.download_and_extract_release_id",
            new_callable=AsyncMock,
        ) as mock_get_release_id,
    ):
        mock_get_release_id.side_effect = regen_base.MissingReleaseIdError(
            "No ReleaseId found in SBOM 12345"
        )
        caplog_level = logging.ERROR
        for ignore_missing_releaseid in [True, False]:
            sbom_regenerator.args.ignore_missing_releaseid = ignore_missing_releaseid
            if ignore_missing_releaseid:
                caplog_level = logging.DEBUG
            sbom_regenerator.args.fail_fast = True
            with caplog.at_level(caplog_level):
                try:
                    await sbom_regenerator.regenerate_sboms()
                    if not ignore_missing_releaseid:
                        raise AssertionError("expected: error")
                except SystemExit:
                    assert "No ReleaseId found in SBOM 12345" in caplog.text
