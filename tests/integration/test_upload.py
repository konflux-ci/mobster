import re
import subprocess
import time
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from mobster.cmd.upload.upload import TPAUploadReport, TPAUploadSuccess
from tests.integration.utils import prepare_input_sbom

TESTDATA_PATH = Path(__file__).parent.parent / "data"


URN_PATTERN = re.compile(
    r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def assert_report(actual: TPAUploadReport, expected: TPAUploadReport) -> None:
    """
    Verify that the actual UploadReport matches the expected report. URNs are
    not matched, just verified using a regular expression.
    """
    assert set(actual.failure) == set(expected.failure)

    def get_path(s_report: TPAUploadSuccess) -> Path:
        return s_report.path

    assert set(map(get_path, actual.success)) == set(map(get_path, expected.success))

    for success in actual.success:
        assert URN_PATTERN.match(success.urn) is not None


@pytest.mark.asyncio
async def test_upload_tpa_file_integration(
    tpa_base_url: str, tpa_client: TPAClient, tmp_path: Path
) -> None:
    sbom_file = TESTDATA_PATH / "index_manifest_sbom.spdx.json"

    temporary_sbom_name = f"sbom-to-download-{time.time()}"
    test_sbom_path, _ = prepare_input_sbom(
        sbom_file, tmp_path, "sbom.json", temporary_sbom_name
    )

    expected_report = TPAUploadReport(
        success=[TPAUploadSuccess(path=test_sbom_path, urn="")],
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

    actual_report = TPAUploadReport.model_validate_json(result.stdout)
    assert_report(actual_report, expected_report)
