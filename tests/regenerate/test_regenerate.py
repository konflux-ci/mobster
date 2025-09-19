""" tests for module for regenerating SBOM documents """

import asyncio
import json
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
from mobster.regenerate.base import SbomRegenerator
from mobster.release import ReleaseId
from mobster.tekton.s3 import S3Client


def mock_regenerate_args() -> regen_base.RegenerateArgs:
    """ default RegenerateArgs for regenerator tests """
    return regen_base.RegenerateArgs(
        output_path=Path("/test/path"),
        tpa_base_url="https://test.ing",
        s3_bucket_url="https://test-url",
        mobster_versions="1.2.3,4.5.6",
        concurrency=100,
        tpa_retries=20,
        dry_run=True,
        fail_fast=True,
        verbose=False,
        sbom_type=regen_base.SbomType.PRODUCT,
    )


def test_regenerate_args() -> None:
    """ test arg parsing/setup for regenerator """
    args = mock_regenerate_args()
    assert args.output_path == Path("/test/path")
    assert args.tpa_base_url == "https://test.ing"
    assert args.s3_bucket_url == "https://test-url"
    assert args.mobster_versions == "1.2.3,4.5.6"
    assert args.concurrency == 100
    assert args.tpa_retries == 20
    assert args.dry_run is True
    assert args.fail_fast is True
    assert args.verbose is False
    assert args.sbom_type == regen_base.SbomType.PRODUCT


def get_mock_sbom(id: str, name: str) -> SbomSummary:
    """ constructs a SbomSummary object for testing """
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
    id: str, name: str, release_id: str, path: Path
) -> str:
    """ sample downloaded SBOM data for testing """
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
        "annotations": [
            {
                "annotationDate": "2025-08-25T09:34:17Z",
                "annotationType": "OTHER",
                "annotator": "Tool: Mobster-0.6.0",
                "comment": f"release_id={release_id}",
            }
        ],
    }
    return json.dumps(sbom)


@pytest.mark.asyncio
@patch("mobster.cmd.upload.tpa.TPAClient")
async def test_regenerate_sboms(
        mock_tpa_client: AsyncMock,
        mock_env_vars: None,
) -> None:
    """ tests regenerate_sboms() """
    args = mock_regenerate_args()

    sbom1 = get_mock_sbom(id="a", name="sbom_1")

    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom1

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock()

    regenerator = SbomRegenerator(args, regen_base.SbomType.PRODUCT)

    regenerator.tpa_client = mock_tpa_client
    regenerator.regenerate_sbom = AsyncMock()  # type: ignore[method-assign]

    await regenerator.regenerate_sboms()
    regenerator.regenerate_sbom.assert_awaited_with(sbom1)


@pytest.mark.asyncio
async def test_regenerate_sbom_dry_run(
        mock_env_vars: None
) -> None:
    """ tests regenerate_sboms() in dry-run mode """
    args = mock_regenerate_args()
    args.dry_run = True
    mock_sbom = get_mock_sbom(id="abc123", name="sbom-abc123")
    release_id = ReleaseId.new()

    regenerator = SbomRegenerator(args)
    regenerator.get_release_id = AsyncMock(return_value=release_id)  # type: ignore[method-assign]
    regenerator.gather_s3_input_data = AsyncMock(  # type: ignore[method-assign]
        return_value=("path_snapshot", "path_release_data")
    )
    regenerator.process_sboms = AsyncMock()  # type: ignore[method-assign]

    await regenerator.regenerate_sbom(mock_sbom)

    regenerator.get_release_id.assert_awaited_once_with(mock_sbom)
    regenerator.gather_s3_input_data.assert_awaited_once_with(
        release_id
    )


@pytest.mark.asyncio
async def test_regenerate_sbom_non_dry_run(
        mock_env_vars: None
) -> None:
    """ tests regenerate_sboms() in "live" (non dry-run) mode """
    args = mock_regenerate_args()
    args.dry_run = False
    sbom_id = "123456"
    sbom_name = "test_sbom"
    release_id = ReleaseId.new()
    mock_sbom = get_mock_sbom(id=sbom_id, name=sbom_name)
    mock_tpa_client = AsyncMock()
    mock_tpa_client.delete_sbom.return_value = AsyncMock(status_code=200)

    path_snapshot = Path("/path/to/snapshot")
    path_release_data = Path("/path/to/release_data")
    regenerator = SbomRegenerator(args)
    regenerator.get_release_id = AsyncMock(return_value=release_id)  # type: ignore[method-assign]
    regenerator.gather_s3_input_data = AsyncMock(  # type: ignore[method-assign]
        return_value=(path_snapshot, path_release_data)
    )
    regenerator.process_sboms = AsyncMock()  # type: ignore[method-assign]
    regenerator.tpa_client = mock_tpa_client
    regenerator.delete_sbom = AsyncMock()  # type: ignore[method-assign]
    regenerator.delete_sbom.return_value = httpx.Response(status_code=200)

    await regenerator.regenerate_sbom(mock_sbom)

    regenerator.get_release_id.assert_awaited_once()
    regenerator.gather_s3_input_data.assert_awaited_once()

    regenerator.process_sboms.assert_awaited_once()
    regenerator.delete_sbom.assert_awaited_once()


def test_gather_s3_input_data(
        mock_env_vars: None
) -> None:
    """ tests fetching S3 bucket data """
    args = mock_regenerate_args()
    sbom_regenerator = SbomRegenerator(args)
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
        "--mobster-versions",
        "0.1.2,3.4.5",
        "--concurrency",
        "500",
        "--tpa-retries",
        "300",
        "--dry-run",
        "--non-fail-fast",
        "--verbose",
    ]


def test_parse_args(
        tmp_path: Path,
        dummy_args: list[str],
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the parse_args function for proper argument parsing."""
    monkeypatch.setattr("sys.argv", ["program_name"] + dummy_args)
    args = regen_base.parse_args()
    assert isinstance(args, regen_base.RegenerateArgs)
    assert args.output_path == Path(tmp_path / "output")
    assert args.tpa_base_url == "https://tpa.url"
    assert args.s3_bucket_url == "https://s3.url/bucket"
    assert args.mobster_versions == "0.1.2,3.4.5"
    assert args.concurrency == 500
    assert args.tpa_retries == 300
    assert args.dry_run is True
    assert args.fail_fast is False
    assert args.verbose is True


def test_prepare_output_paths(tmp_path: Path) -> None:
    """ verify prepare_output_paths ensures the required dirs exist """
    test_output_path = tmp_path / "output"
    regen_base.prepare_output_paths(str(test_output_path))
    assert (test_output_path / "release-data").exists()
    assert (test_output_path / "snapshots").exists()


def test_prepare_output_paths_with_existing_path(tmp_path: Path) -> None:
    """ verify prepare_output_paths ensures the required dirs exist """
    output_path = tmp_path / "output"
    (output_path / S3Client.release_data_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / S3Client.snapshot_prefix).mkdir(parents=True, exist_ok=True)

    regen_base.prepare_output_paths(str(output_path))

    release_data_dir = output_path / S3Client.release_data_prefix
    snapshot_dir = output_path / S3Client.snapshot_prefix

    assert release_data_dir.is_dir()
    assert snapshot_dir.is_dir()
    assert os.path.exists(release_data_dir)
    assert os.path.exists(snapshot_dir)


def test_prepare_output_paths_with_nonexisting_path(tmp_path: Path) -> None:
    """ verify prepare_output_paths ensures the required dirs exist """
    output_path = tmp_path / "foobar12345"
    regen_base.prepare_output_paths(str(output_path))

    release_data_dir = output_path / S3Client.release_data_prefix
    snapshot_dir = output_path / S3Client.snapshot_prefix

    assert output_path.is_dir()
    assert release_data_dir.is_dir()
    assert snapshot_dir.is_dir()


def test_extract_release_id_with_annotations() -> None:
    """ verify extract_release_id handles annotations """
    expected_release_id = ReleaseId.new()
    sbom_dict = {
        "annotations": [
            {"comment": f"release_id={expected_release_id.id}"},
        ]
    }
    result = SbomRegenerator.extract_release_id(sbom_dict)
    assert expected_release_id.id == result.id


def test_extract_release_id_with_properties() -> None:
    """ verify extract_release_id handles properties """
    expected_release_id = ReleaseId.new()
    sbom_dict = {
        "properties": [
            {"name": "release_id", "value": f"{expected_release_id.id}"},
        ]
    }
    result = SbomRegenerator.extract_release_id(sbom_dict)
    assert expected_release_id.id == result.id


def sbom_from_dict(sbom_dict: dict[str, Any]) -> SbomSummary:
    """ convenience test function to unmarshal SBOMSummary from dict """
    return json.loads(json.dumps(sbom_dict))  # type: ignore[no-any-return]


def test_extract_release_id_missing() -> None:
    """ verify extract_release_id handles missing ReleaseId """
    sbom_dict = {
        "annotations": [
            {"comment": "etc"},
        ],
        "properties": [
            {"name": "foo", "value": "bar"},
        ],
    }
    try:
        SbomRegenerator.extract_release_id(sbom_dict)
        # shouldn't get here, so fail
        raise AssertionError()
    except ValueError:
        # expected
        assert True


def test_download_and_extract_release_id_success(
        mock_env_vars: None
) -> None:
    summary = get_mock_sbom(id="sbom_id_1", name="test_sbom")
    expected_release_id = ReleaseId.new()

    args = mock_regenerate_args()
    regenerator = SbomRegenerator(args)
    regenerator.get_tpa_client = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(download_sbom=AsyncMock())
    )
    regenerator.extract_release_id = MagicMock(  # type: ignore[method-assign]
        return_value=expected_release_id
    )

    sbom_path = Path("/mock/path/test_sbom.json")
    regenerator.args.output_path = sbom_path.parent

    with patch("aiofiles.open", new_callable=MagicMock) as mocked_open:
        mocked_open.return_value.__aenter__.return_value.read = AsyncMock(
            return_value=json.dumps({"mock_key": "mock_value"})
        )
        asyncio.run(regenerator.download_and_extract_release_id(summary))

    regenerator.get_tpa_client().download_sbom.assert_awaited_once_with(
        summary.id, sbom_path
    )
    mocked_open.return_value.__aenter__.return_value.read.assert_awaited_once()
    regenerator.extract_release_id.assert_called_once_with(
        {"mock_key": "mock_value"}
    )


def test_download_and_extract_release_id_file_not_found_error(
        mock_env_vars: None
) -> None:
    summary = get_mock_sbom(id="sbom_id_2", name="test_sbom_error")
    args = mock_regenerate_args()
    regenerator = SbomRegenerator(args)
    regenerator.get_tpa_client = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(download_sbom=AsyncMock())
    )
    regenerator.args.output_path = Path("/mock/path")

    with patch("aiofiles.open", side_effect=FileNotFoundError), patch(
            "asyncio.sleep", new_callable=AsyncMock
    ) as mocked_sleep:
        try:
            asyncio.run(regenerator.download_and_extract_release_id(summary))
        except ValueError as e:
            assert "Unable to extract ReleaseId" in str(e)

    regenerator.get_tpa_client().download_sbom.assert_awaited()
    mocked_sleep.assert_awaited()


def test_download_and_extract_release_id_invalid_json_error(
        mock_env_vars: None
) -> None:
    summary = get_mock_sbom(id="sbom_id_3", name="test_sbom_invalid_json")
    args = mock_regenerate_args()
    regenerator = SbomRegenerator(args)
    regenerator.get_tpa_client = MagicMock(  # type: ignore[method-assign]
        return_value=MagicMock(download_sbom=AsyncMock())
    )
    regenerator.args.output_path = Path("/mock/path")

    with patch("aiofiles.open", new_callable=MagicMock) as mocked_open, patch(
            "asyncio.sleep", new_callable=AsyncMock
    ) as mocked_sleep:
        mocked_open.return_value.__aenter__.return_value.read = AsyncMock(
            side_effect=json.JSONDecodeError("Expecting value", "mock_doc", 0)
        )

        try:
            asyncio.run(regenerator.download_and_extract_release_id(summary))
        except ValueError as e:
            assert "Unable to extract ReleaseId" in str(e)

    regenerator.get_tpa_client().download_sbom.assert_awaited()
    mocked_open.return_value.__aenter__.return_value.read.assert_awaited()
    mocked_sleep.assert_awaited()


async def async_test_wrapper(the_coro: Coroutine[Any, Any, Any]) -> Any:
    """ convenience test wrapper for coroutine """
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
