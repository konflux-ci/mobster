import os
import subprocess
from pathlib import Path

TESTDATA_PATH = Path(__file__).parent.parent / "data"


def test_upload_tpa_file_integration(tpa_base_url: str) -> None:
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    test_env = os.environ.copy()
    test_env.update({"MOBSTER_TPA_AUTH_DISABLE": "true"})

    result = subprocess.run(
        [
            "mobster",
            "upload",
            "tpa",
            "--tpa-base-url",
            tpa_base_url,
            "--file",
            str(sbom_file),
        ],
        capture_output=True,
        text=True,
        env=test_env,
    )

    assert result.returncode == 0, f"Command failed with stderr: {result.stderr}"
