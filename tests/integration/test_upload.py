import subprocess
import time
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from mobster.cmd.upload.upload import UploadReport
from tests.integration.utils import (
    prepare_input_sbom,
    verify_sboms_uploaded,
)

TESTDATA_PATH = Path(__file__).parent.parent / "data"


def run_upload_command(
    tpa_base_url: str, extra_args: list[str]
) -> subprocess.CompletedProcess[bytes]:
    """
    Run the mobster upload command with common arguments.

    Args:
        tpa_base_url: The TPA base URL
        extra_args: Additional command line arguments

    Returns:
        The completed subprocess result
    """
    cmd = [
        "mobster",
        "upload",
        "tpa",
        "--tpa-base-url",
        tpa_base_url,
    ]
    cmd.extend(extra_args)

    return subprocess.run(cmd, capture_output=True)


@pytest.mark.asyncio
async def test_upload_tpa_file(
    tpa_base_url: str,
    tpa_client: TPAClient,
    tpa_auth_env: dict[str, str],
    tmp_path: Path,
) -> None:
    """
    Test uploading a single SBOM file to TPA using the command line interface.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    temporary_sbom_name = f"sbom-to-download-{time.time()}"
    test_sbom_path, _ = prepare_input_sbom(
        sbom_file, tmp_path, "sbom.json", temporary_sbom_name
    )

    expected_report = UploadReport(
        success=[test_sbom_path],
        failure=[],
    )

    result = run_upload_command(
        tpa_base_url, ["--file", str(test_sbom_path), "--report"]
    )

    assert result.returncode == 0, (
        f"Command failed with stderr: {result.stderr.decode()}"
    )

    # Verify SBOM was uploaded to TPA
    await verify_sboms_uploaded(tpa_client, [temporary_sbom_name])

    actual_report = UploadReport.model_validate_json(result.stdout)
    assert actual_report == expected_report, (
        "Upload report does not match expected report."
    )


@pytest.mark.asyncio
async def test_upload_tpa_from_directory(
    tpa_base_url: str,
    tpa_client: TPAClient,
    tpa_auth_env: dict[str, str],
    tmp_path: Path,
) -> None:
    """
    Test uploading multiple SBOM files from a directory.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    test_sboms = []
    sbom_names = []
    for i in range(2):
        sbom_name = f"test-sbom-{i}-{time.time()}"
        test_sbom_path, _ = prepare_input_sbom(
            sbom_file, tmp_path, f"sbom_{i}.json", sbom_name
        )
        test_sboms.append(test_sbom_path)
        sbom_names.append(sbom_name)

    result = run_upload_command(tpa_base_url, ["--from-dir", str(tmp_path), "--report"])

    assert result.returncode == 0, (
        f"Command failed with stderr: {result.stderr.decode()}"
    )

    actual_report = UploadReport.model_validate_json(result.stdout)
    assert len(actual_report.success) == 2
    assert len(actual_report.failure) == 0

    success_names = {p.name for p in actual_report.success}
    expected_names = {p.name for p in test_sboms}
    assert success_names == expected_names

    # Verify SBOMs were actually uploaded to TPA
    await verify_sboms_uploaded(tpa_client, sbom_names)


def test_upload_tpa_nonexistent_file_failure(
    tpa_base_url: str, tpa_auth_env: dict[str, str]
) -> None:
    """
    Test upload failure when trying to upload a nonexistent file.
    """
    result = run_upload_command(tpa_base_url, ["--file", "/nonexistent/file.json"])

    assert result.returncode != 0, "Expected command to fail with nonexistent file"
