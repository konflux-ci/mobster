import json
import subprocess
import time
from pathlib import Path

from mobster.cmd.upload.tpa import TPAClient
from tests.integration.utils import prepare_input_sbom

TESTDATA_PATH = Path(__file__).parent.parent / "data"


def test_download_tpa_file_integration(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    temporary_sbom_name = f"sbom-to-download-{time.time()}"
    test_sbom_path, sbom_file_content = prepare_input_sbom(
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
            "download",
            "tpa",
            "--tpa-base-url",
            tpa_base_url,
            "--output",
            tmp_path,
            "--query",
            f"name={temporary_sbom_name}",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Download command failed with stderr: {result.stderr}"
    )

    downloaded_files = list(tmp_path.glob("*.json"))
    assert len(downloaded_files) > 0, "No SBOM files were downloaded"

    assert f"{temporary_sbom_name}.json" in [file.name for file in downloaded_files], (
        "Downloaded SBOM file is not as expected"
    )

    with open(downloaded_files[0]) as downloaded_file:
        downloaded_content = json.load(downloaded_file)

    assert sbom_file_content == downloaded_content, (
        "Downloaded SBOM content does not match the original content"
    )
