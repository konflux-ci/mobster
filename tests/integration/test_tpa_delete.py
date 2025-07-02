import subprocess
import time
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from tests.integration.utils import prepare_input_sbom

TESTDATA_PATH = Path(__file__).parent.parent / "data"


@pytest.mark.asyncio
async def test_delete_tpa_file_integration(
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

    result = subprocess.run(
        [
            "mobster",
            "delete",
            "tpa",
            "--tpa-base-url",
            tpa_base_url,
            "--query",
            f"name={temporary_sbom_name}",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Download command failed with stderr: {result.stderr}"
    )
    sboms = tpa_client.list_sboms(query=f"name={temporary_sbom_name}", sort="ingested")
    sbom_list = [sbom async for sbom in sboms]
    assert len(sbom_list) == 0, "SBOM was not deleted successfully"
