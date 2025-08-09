import json
import subprocess
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from tests.integration.utils import prepare_input_sbom, upload_test_sbom

TESTDATA_PATH = Path(__file__).parent.parent / "data"


def run_download_command(
    tpa_base_url: str, output_dir: Path, query: str
) -> subprocess.CompletedProcess[str]:
    """
    Run the mobster download command.

    Args:
        tpa_base_url: The TPA base URL
        output_dir: Directory to download files to
        query: The query string for download

    Returns:
        The completed subprocess result
    """
    result = subprocess.run(
        [
            "mobster",
            "download",
            "tpa",
            "--tpa-base-url",
            tpa_base_url,
            "--output",
            str(output_dir),
            "--query",
            query,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Download command failed with stderr: {result.stderr}"
    )
    return result


@pytest.mark.asyncio
async def test_download_tpa_file_integration(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    """
    Test downloading a single SBOM file from TPA.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    # provide invalid file name to check name normalization runs
    temporary_sbom_name = "quay.io/foo/bar:1"
    test_sbom_path, sbom_file_content = prepare_input_sbom(
        sbom_file, tmp_path, "sbom.json", temporary_sbom_name
    )

    await upload_test_sbom(tpa_client, test_sbom_path)

    download_output = tmp_path / "downloads"
    download_output.mkdir()

    run_download_command(tpa_base_url, download_output, f"name={temporary_sbom_name}")

    downloaded_files = list(download_output.iterdir())
    assert len(downloaded_files) > 0, "No SBOM files were downloaded"

    assert "quay.io_foo_bar_1.json" in [file.name for file in downloaded_files], (
        "Downloaded SBOM file is not as expected"
    )

    with open(downloaded_files[0]) as downloaded_file:
        downloaded_content = json.load(downloaded_file)

    assert sbom_file_content == downloaded_content, (
        "Downloaded SBOM content does not match the original content"
    )


def test_download_tpa_empty_query_results(
    tpa_base_url: str, tmp_path: Path, tpa_auth_env: dict[str, str]
) -> None:
    """
    Test downloading when no SBOMs match the query.
    """
    run_download_command(tpa_base_url, tmp_path, "name=nonexistent-sbom-name")
    downloaded_files = list(tmp_path.iterdir())
    assert len(downloaded_files) == 0, "Expected no downloaded files for empty query"


@pytest.mark.asyncio
async def test_download_tpa_multiple_sboms(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    """
    Test downloading multiple SBOMs with a query filter.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    test_prefix = "multi-download"
    sbom_names = [
        f"{test_prefix}-sbom-1",
        f"{test_prefix}-sbom-2",
        f"{test_prefix}-sbom-3",
    ]

    for sbom_name in sbom_names:
        test_sbom_path, _ = prepare_input_sbom(
            sbom_file, tmp_path, f"{sbom_name}.json", sbom_name
        )
        await upload_test_sbom(tpa_client, test_sbom_path)

    download_output = tmp_path / "downloads"
    download_output.mkdir()

    run_download_command(tpa_base_url, download_output, f"name~{test_prefix}")

    downloaded_files = list(download_output.iterdir())
    assert len(downloaded_files) == 3, (
        f"Expected 3 downloaded files, got {len(downloaded_files)}"
    )

    downloaded_names = {file.stem for file in downloaded_files}
    expected_names = set(sbom_names)
    assert downloaded_names == expected_names, (
        f"Downloaded file names {downloaded_names} "
        f"don't match expected {expected_names}"
    )


def test_download_tpa_invalid_url(tmp_path: Path) -> None:
    """
    Test download failure when TPA URL is invalid.
    """
    download_output = tmp_path / "downloads"
    download_output.mkdir()

    result = subprocess.run(
        [
            "mobster",
            "download",
            "tpa",
            "--tpa-base-url",
            "https://invalid-tpa-url.example.com",
            "--output",
            str(download_output),
            "--query",
            "name=test",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0, "Expected download to fail with invalid TPA URL"
