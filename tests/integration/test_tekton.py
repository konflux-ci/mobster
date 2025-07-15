"""
This module contains integration tests for scripts used in release Tekton
tasks.
"""

import subprocess
from pathlib import Path

import pytest

from mobster.cmd.upload.upload import TPAUploadReport, TPAUploadSuccess
from mobster.report import ComponentReport, MobsterReport, ProductReport


@pytest.mark.parametrize(
    ["report_type", "tpa_report", "failed_dir_contents", "expected_report"],
    [
        pytest.param(
            "component",
            TPAUploadReport(
                success=[TPAUploadSuccess(path=Path("sbom.json"), urn="urn_dummy")],
                failure=[Path("failed.json")],
            ),
            [Path("failed.json")],
            ComponentReport(
                mobster_component_report=MobsterReport(
                    tpa=[TPAUploadSuccess(path=Path("sbom.json"), urn="urn_dummy")],
                    failure=[Path("failed.json")],
                )
            ),
            id="tpa-success-failure-and-s3-failure",
        ),
        pytest.param(
            "product",
            TPAUploadReport(
                success=[TPAUploadSuccess(path=Path("sbom.json"), urn="urn_dummy")],
                failure=[Path("failed.json")],
            ),
            [],
            ProductReport(
                mobster_product_report=MobsterReport(
                    tpa=[TPAUploadSuccess(path=Path("sbom.json"), urn="urn_dummy")],
                    failure=[],
                )
            ),
            id="tpa-success-failure-and-s3-push-success",
        ),
    ],
)
def test_generate_upload_report(
    tmp_path: Path,
    report_type: str,
    tpa_report: TPAUploadReport,
    failed_dir_contents: list[Path],
    expected_report: ProductReport | ComponentReport,
) -> None:
    data_dir = tmp_path
    tpa_report_path = data_dir / "tpa_report.json"
    result = data_dir / "result.json"

    failed_dir = data_dir / "failed-sboms"
    failed_dir.mkdir()

    # Dump the input TPA report to a file
    with open(tpa_report_path, "w", encoding="utf-8") as fp:
        fp.write(tpa_report.model_dump_json())

    # If any failed SBOMs weren't pushed to S3, they are still in the
    # failed-dir
    for fpath in failed_dir_contents:
        (failed_dir / fpath).touch()

    res = subprocess.run(
        [
            "generate_upload_report",
            "--data-dir",
            data_dir,
            "--tpa-report",
            tpa_report_path,
            "--failed-dir",
            failed_dir,
            "--type",
            report_type,
            "--result",
            result,
        ]
    )

    assert res.returncode == 0

    if report_type == "component":
        report_cls: type[ComponentReport] | type[ProductReport] = ComponentReport
    else:
        report_cls = ProductReport

    # Verify that the result was written to and contains a valid report.
    with open(result) as fp:
        report = report_cls.model_validate_json(fp.read())

    # Verify that the report matches the expected report.
    assert report == expected_report
