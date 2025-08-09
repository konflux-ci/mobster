import subprocess
import time
from pathlib import Path

import httpx
import pytest

from mobster.cmd.upload.tpa import TPAClient
from tests.integration.utils import prepare_input_sbom

TESTDATA_PATH = Path(__file__).parent.parent / "data"


async def upload_test_sbom(tpa_client: TPAClient, sbom_path: Path) -> httpx.Response:
    """
    Upload a test SBOM and verify it was successful.

    Args:
        tpa_client: The TPA client to use for upload
        sbom_path: Path to the SBOM file to upload

    Returns:
        The HTTP response from the upload
    """
    response = await tpa_client.upload_sbom(sbom_path)
    assert isinstance(response, httpx.Response)
    assert response.status_code == 201, f"Upload failed: {response.text}"
    return response


def run_delete_command(
    tpa_base_url: str, query: str, dry_run: bool = False
) -> subprocess.CompletedProcess[str]:
    """
    Run the mobster delete command and verify it was successful.

    Args:
        tpa_base_url: The TPA base URL
        query: The query string for deletion
        dry_run: Whether to run in dry-run mode

    Returns:
        The completed subprocess result
    """
    cmd = [
        "mobster",
        "delete",
        "tpa",
        "--tpa-base-url",
        tpa_base_url,
        "--query",
        query,
    ]
    if dry_run:
        cmd.append("--dry-run")

    return subprocess.run(cmd, capture_output=True, text=True)


async def count_sboms_matching(tpa_client: TPAClient, query: str) -> int:
    """
    Count the number of SBOMs matching a query.

    Args:
        tpa_client: The TPA client to use for querying
        query: The query string to match SBOMs

    Returns:
        Number of matching SBOMs
    """
    sboms = tpa_client.list_sboms(query=query, sort="ingested")
    sbom_list = [sbom async for sbom in sboms]
    return len(sbom_list)


@pytest.mark.asyncio
async def test_delete_tpa_file(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    temporary_sbom_name = f"sbom-to-delete-{time.time()}"
    test_sbom_path, _ = prepare_input_sbom(
        sbom_file, tmp_path, "sbom.json", temporary_sbom_name
    )

    result = subprocess.run(
        [
            "mobster",
            "upload",
            "tpa",
            "--tpa-base-url",
            tpa_base_url,
            "--file",
            str(test_sbom_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"Command failed with stderr: {result.stderr}"

    result = run_delete_command(tpa_base_url, f"name={temporary_sbom_name}")
    assert result.returncode == 0, "Delete command exited with non-zero code"

    count = await count_sboms_matching(tpa_client, f"name={temporary_sbom_name}")
    assert count == 0, "SBOM was not deleted successfully"


@pytest.mark.asyncio
async def test_delete_tpa_dry_run(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    """
    Test dry-run mode - SBOM should not be deleted.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    temporary_sbom_name = "sbom-dry-run"
    test_sbom_path, _ = prepare_input_sbom(
        sbom_file, tmp_path, "sbom.json", temporary_sbom_name
    )

    await upload_test_sbom(tpa_client, test_sbom_path)

    result = run_delete_command(
        tpa_base_url, f"name={temporary_sbom_name}", dry_run=True
    )
    assert result.returncode == 0, "Delete command exited with non-zero code"

    count = await count_sboms_matching(tpa_client, f"name={temporary_sbom_name}")
    assert count == 1, "SBOM was deleted despite dry-run flag"


@pytest.mark.asyncio
async def test_delete_tpa_multiple(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    """
    Test deleting multiple SBOMs with a query filter while preserving others.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    test_prefix = "multi-delete"
    sbom_names_to_delete = [
        f"{test_prefix}-sbom-1",
        f"{test_prefix}-sbom-2",
        f"{test_prefix}-sbom-3",
    ]

    other_sbom_name = "other-sbom"

    all_sbom_names = sbom_names_to_delete + [other_sbom_name]

    for sbom_name in all_sbom_names:
        test_sbom_path, _ = prepare_input_sbom(
            sbom_file, tmp_path, f"{sbom_name}.json", sbom_name
        )
        await upload_test_sbom(tpa_client, test_sbom_path)

    result = run_delete_command(tpa_base_url, f"name~{test_prefix}")
    assert result.returncode == 0, "Delete command exited with non-zero code"

    # verify SBOMs with prefix were deleted
    prefix_count = await count_sboms_matching(tpa_client, f"name~{test_prefix}")
    assert prefix_count == 0, (
        f"Expected 0 SBOMs with prefix after deletion, found {prefix_count}"
    )

    # verify the other SBOM was NOT deleted
    other_count = await count_sboms_matching(tpa_client, f"name={other_sbom_name}")
    assert other_count == 1, f"Other SBOM was incorrectly deleted, found {other_count}"


@pytest.mark.asyncio
async def test_delete_tpa_empty_query(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    """
    Test delete with empty query - should delete all SBOMs.
    """
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    sbom_names = ["empty-query-test-1", "empty-query-test-2"]

    for sbom_name in sbom_names:
        test_sbom_path, _ = prepare_input_sbom(
            sbom_file, tmp_path, f"{sbom_name}.json", sbom_name
        )
        await upload_test_sbom(tpa_client, test_sbom_path)

    result = run_delete_command(tpa_base_url, "")
    assert result.returncode == 0, "Delete command exited with non-zero code"

    final_count = await count_sboms_matching(tpa_client, "")
    assert final_count == 0, f"Expected 0 SBOMs after deletion, found {final_count}"


@pytest.mark.asyncio
async def test_delete_invalid_url() -> None:
    result = run_delete_command("localhost:8080/invalid_url", "")
    assert result.returncode == 1, "TPA delete did not fail with invalid URL"
