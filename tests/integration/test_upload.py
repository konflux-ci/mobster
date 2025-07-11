import subprocess
import time
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from mobster.cmd.upload.upload import UploadReport
from tests.integration.utils import prepare_input_sbom

TESTDATA_PATH = Path(__file__).parent.parent / "data"


@pytest.mark.asyncio
async def test_upload_tpa_file_integration(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    temporary_sbom_name = f"sbom-to-download-{time.time()}"
    test_sbom_path, _ = prepare_input_sbom(
        sbom_file, tmp_path, "sbom.json", temporary_sbom_name
    )

    expected_report = UploadReport(
        success=[test_sbom_path],
        failure=[],
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
            "--report",
        ],
        capture_output=True,
    )

    assert result.returncode == 0, (
        f"Command failed with stderr: {result.stderr.decode()}"
    )
    tpa_client.list_sboms(query=f"name={temporary_sbom_name}", sort="ingested")
    sboms = tpa_client.list_sboms(query="", sort="ingested")
    all_sboms = [sbom async for sbom in sboms]
    assert len(all_sboms) > 0, "No SBOMs found in TPA after upload"
    assert any(sbom.name == temporary_sbom_name for sbom in all_sboms), (
        f"Uploaded SBOM with name {temporary_sbom_name} not found in TPA"
    )

    actual_report = UploadReport.model_validate_json(result.stdout)
    assert actual_report == expected_report, (
        "Upload report does not match expected report."
    )
