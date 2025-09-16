import asyncio
import httpx
import json
import os
import pytest
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import mobster.regenerate.base as regen_base
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import TPAClient
from mobster.regenerate.base import SbomRegenerator
from mobster.release import ReleaseId
from mobster.tekton.s3 import S3Client


def get_regenerate_args() -> regen_base.RegenerateArgs:
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


def get_mock_release_id(last_three_caharacters: str) -> str:
    return f"2587e906-b2ab-47cd-b78a-53e406197{last_three_caharacters}"


def test_regenerate_args() -> None:
    args = get_regenerate_args()
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
    return SbomSummary(
        id=id,
        name=name,
        ingested=datetime.now().isoformat(),
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
    mock_env_vars: MagicMock,
    mock_tpa_client: AsyncMock,
) -> None:
    args = get_regenerate_args()

    sbom1 = get_mock_sbom(id="a", name="sbom_1")

    async def mock_list_sboms(query: str, sort: str) -> Any:
        yield sbom1

    mock_tpa_client.list_sboms.return_value = mock_list_sboms("", "")
    mock_tpa_client.download_sbom = AsyncMock()

    regenerator = regen_base.SbomRegenerator(args, regen_base.SbomType.PRODUCT)

    regenerator.tpa_client = mock_tpa_client
    regenerator.regenerate_sbom = AsyncMock()

    await regenerator.regenerate_sboms()
    regenerator.regenerate_sbom.assert_awaited_with(sbom1)


@pytest.mark.asyncio
async def test_regenerate_sbom_dry_run() -> None:
    args = get_regenerate_args()
    args.dry_run = True
    mock_sbom = get_mock_sbom(id="abc123", name="sbom-abc123")

    regenerator = SbomRegenerator(args)
    regenerator.get_release_id = AsyncMock(return_value=get_mock_release_id("123"))
    regenerator.gather_s3_input_data = AsyncMock(
        return_value=("path_snapshot", "path_release_data")
    )
    regenerator.process_sboms = AsyncMock()

    await regenerator.regenerate_sbom(mock_sbom)

    regenerator.get_release_id.assert_awaited_once_with(mock_sbom)
    regenerator.gather_s3_input_data.assert_awaited_once_with(
        get_mock_release_id("123")
    )


@pytest.mark.asyncio
async def test_regenerate_sbom_non_dry_run(mock_env_vars: MagicMock) -> None:
    args = get_regenerate_args()
    args.dry_run = False
    sbom_id = "123456"
    sbom_name = "test_sbom"
    release_id_str = get_mock_release_id("456")
    mock_sbom = get_mock_sbom(id=sbom_id, name=sbom_name)
    mock_tpa_client = AsyncMock()
    mock_tpa_client.delete_sbom.return_value = AsyncMock(status_code=200)

    path_snapshot = Path("/path/to/snapshot")
    path_release_data = Path("/path/to/release_data")
    regenerator = SbomRegenerator(args)
    regenerator.get_release_id = AsyncMock(return_value=ReleaseId(release_id_str))
    regenerator.gather_s3_input_data = AsyncMock(
        return_value=(path_snapshot, path_release_data)
    )
    regenerator.process_sboms = AsyncMock()
    regenerator.tpa_client = mock_tpa_client
    regenerator.delete_sbom = AsyncMock()
    regenerator.delete_sbom.return_value = httpx.Response(status_code=200)

    await regenerator.regenerate_sbom(mock_sbom)

    regenerator.get_release_id.assert_awaited_once()
    regenerator.gather_s3_input_data.assert_awaited_once()

    regenerator.process_sboms.assert_awaited_once()
    regenerator.delete_sbom.assert_awaited_once()


def test_gather_s3_input_data(mock_env_vars: MagicMock) -> None:
    args = get_regenerate_args()
    sbom_regenerator = SbomRegenerator(args)
    sbom_regenerator.s3_client = AsyncMock(spec=S3Client)
    rid = ReleaseId(get_mock_release_id("abc"))

    path_snapshot = args.output_path / S3Client.snapshot_prefix / f"{rid}.snapshot.json"
    path_release_data = (
        args.output_path / S3Client.release_data_prefix / f"{rid}.release_data.json"
    )

    async def async_test():
        result = await sbom_regenerator.gather_s3_input_data(rid)

        assert result == (path_snapshot, path_release_data)
        sbom_regenerator.s3_client.get_snapshot.assert_awaited_once_with(
            path_snapshot, rid
        )
        sbom_regenerator.s3_client.get_release_data.assert_awaited_once_with(
            path_release_data, rid
        )

    asyncio.run(async_test())


@pytest.fixture
def dummy_args(tmp_path):
    """Fixture to simulate command line arguments."""
    return [
        "--output-path",
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
        "True",
        "--non-fail-fast",
        "True",
        "--verbose",
        "True",
    ]


def test_parse_args(tmp_path, dummy_args, monkeypatch):
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


def test_prepare_output_paths(tmp_path):
    """Test if prepare_output_paths creates the required directories."""
    test_output_path = tmp_path / "output"
    regen_base.prepare_output_paths(test_output_path)
    assert (test_output_path / "release-data").exists()
    assert (test_output_path / "snapshots").exists()


def test_prepare_output_paths_with_existing_path(tmp_path: Path) -> None:
    output_path = tmp_path / "output"
    (output_path / S3Client.release_data_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / S3Client.snapshot_prefix).mkdir(parents=True, exist_ok=True)

    regen_base.prepare_output_paths(output_path)

    release_data_dir = output_path / S3Client.release_data_prefix
    snapshot_dir = output_path / S3Client.snapshot_prefix

    assert release_data_dir.is_dir()
    assert snapshot_dir.is_dir()
    assert os.path.exists(release_data_dir)
    assert os.path.exists(snapshot_dir)


def test_prepare_output_paths_with_nonexisting_path(tmp_path: Path) -> None:
    output_path = tmp_path / "foobar12345"
    regen_base.prepare_output_paths(output_path)

    release_data_dir = output_path / S3Client.release_data_prefix
    snapshot_dir = output_path / S3Client.snapshot_prefix

    assert output_path.is_dir()
    assert release_data_dir.is_dir()
    assert snapshot_dir.is_dir()


def test_extract_release_id_with_annotations() -> None:
    expected_release_id = ReleaseId(get_mock_release_id("123"))
    sbom = {
        "annotations": [
            {"comment": f"release_id={expected_release_id}"},
        ]
    }
    result = SbomRegenerator.extract_release_id(sbom)
    assert expected_release_id.id == result.id


def test_extract_release_id_with_properties() -> None:
    expected_release_id = ReleaseId(get_mock_release_id("456"))
    sbom = {
        "properties": [
            {"name": "release_id", "value": f"{expected_release_id}"},
        ]
    }
    result = SbomRegenerator.extract_release_id(sbom)
    assert expected_release_id.id == result.id


def test_extract_release_id_missing() -> None:
    sbom = {
        "annotations": [
            {"comment": "etc"},
        ],
        "properties": [
            {"name": "foo", "value": "bar"},
        ],
    }

    result = SbomRegenerator.extract_release_id(sbom)
    assert result is None


async def async_test_wrapper(the_coro):
    return await the_coro


def test_download_and_extract_release_id_success() -> None:
    sbom = get_mock_sbom(id="12345", name="test-sbom")
    expected_release_id = get_mock_release_id("123")
    mocked_client = AsyncMock()
    mocked_args = MagicMock()
    mocked_args.output_path = MagicMock()
    mocked_args.output_path.__truediv__.return_value = "/mock/path/test-sbom.json"

    regenerator = SbomRegenerator(args=mocked_args)
    regenerator.tpa_client = mocked_client
    regenerator.extract_release_id = MagicMock(return_value=expected_release_id)

    with patch(
        "builtins.open", mock_open(read_data=json.dumps({"id": "release-data"}))
    ):
        release_id = asyncio.run(
            async_test_wrapper(regenerator.download_and_extract_release_id(sbom))
        )

    mocked_client.download_sbom.assert_awaited_once_with(
        "12345", "/mock/path/test-sbom.json"
    )
    assert regenerator.extract_release_id.called
    assert release_id == expected_release_id


def test_download_and_extract_release_id_file_not_found() -> None:
    sbom = get_mock_sbom(id="12345", name="test-sbom")
    mocked_client = AsyncMock()
    mocked_args = MagicMock()
    mocked_args.output_path = MagicMock()
    mocked_args.output_path.__truediv__.return_value = "/mock/path/test-sbom.json"

    regenerator = SbomRegenerator(args=mocked_args)
    regenerator.tpa_client = mocked_client

    with patch("builtins.open", side_effect=FileNotFoundError):
        release_id = asyncio.run(
            async_test_wrapper(regenerator.download_and_extract_release_id(sbom))
        )

    mocked_client.download_sbom.assert_awaited_once_with(
        "12345", "/mock/path/test-sbom.json"
    )
    assert release_id is None


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables needed for the TPA upload command."""
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN_URL", "https://test.token.url")
    monkeypatch.setenv("MOBSTER_TPA_SSO_ACCOUNT", "test-account")
    monkeypatch.setenv("MOBSTER_TPA_SSO_TOKEN", "test-token")
    monkeypatch.setenv("MOBSTER_S3_ACCESS_KEY", "test-access-key")
    monkeypatch.setenv("MOBSTER_S3_SECRET_KEY", "test-secret-key")


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
