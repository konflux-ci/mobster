"""
This module contains integration tests for scripts used in release Tekton
tasks.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from mobster.cmd.upload.upload import TPAUploadReport, TPAUploadSuccess
from mobster.report import ComponentReport, MobsterReport, ProductReport
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.s3 import S3Client


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


@pytest.mark.asyncio
async def test_create_product_sboms_ta_happypath(
    s3_client: S3Client,
    s3_sbom_bucket: str,
    s3_auth_env: dict[str, str],
    tpa_client: TPAClient,
    tpa_base_url: str,
    tpa_auth_env: dict[str, str],
    oci_client: ReferrersTagOCIClient,
    registry_url: str,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path
    snapshot_path = Path("snapshot.json")
    data_path = Path("data.json")
    sbom_path = Path("sboms/")
    failed_sboms_path = Path("failed-sboms")
    tpa_report_path = Path("tpa_report.json")
    final_report_path = Path("final_report.json")
    report_type = "product"

    repo_name = "release"
    image = await oci_client.create_image(repo_name, "latest")
    repo = f"{registry_url.removeprefix('http://')}/{repo_name}"
    snapshot = {
        "components": [
            {
                "name": "component",
                "containerImage": f"{repo}@{image.digest}",
                "rh-registry-repo": "registry.redhat.io/test",
                "tags": ["latest"],
                "repository": repo,
            }
        ]
    }

    with open(data_dir / snapshot_path, "w") as fp:
        json.dump(snapshot, fp)

    release_data = {
        "releaseNotes": {
            "product_name": "Product",
            "product_version": "1.0",
            "cpe": [
                "cpe:/a:acme:product:1.0:update1",
                "cpe:/a:acme:product:1.0:update2",
            ],
        }
    }

    with open(data_dir / data_path, "w") as fp:
        json.dump(release_data, fp)

    run_create_product_sbom(
        data_dir=data_dir,
        snapshot_spec=snapshot_path,
        release_data=data_path,
        sbom_path=sbom_path,
    )
    verify_create_product_sbom(data_dir, sbom_path)

    run_upload_sboms_to_atlas(
        data_dir=data_dir,
        atlas_api_url=tpa_base_url,
        sbom_path=sbom_path,
        report_path=tpa_report_path,
        failed_dir=failed_sboms_path,
        auth_env=tpa_auth_env,
    )
    await verify_upload_sboms_to_atlas(
        data_dir, failed_sboms_path, tpa_report_path, tpa_client, n_sboms=1
    )

    run_upload_sboms_to_s3(
        data_dir=data_dir,
        retry_s3_bucket=s3_sbom_bucket,
        failed_dir=failed_sboms_path,
        auth_env=s3_auth_env,
    )

    run_generate_upload_report(
        data_dir=data_dir,
        tpa_report=tpa_report_path,
        failed_dir=failed_sboms_path,
        result=final_report_path,
        type=report_type,
    )
    verify_generate_upload_report(data_dir, final_report_path)


def verify_create_product_sbom(data_dir: Path, sbom_path: Path) -> None:
    """
    Verify that create_product_sbom script created a product SBOM in the
    expected path.
    """
    assert (data_dir / sbom_path / "sbom.json").exists()


async def verify_upload_sboms_to_atlas(
    data_dir: Path,
    failed_sboms_path: Path,
    tpa_report_path: Path,
    tpa_client: TPAClient,
    n_sboms: int,
) -> None:
    """
    Verify that upload_sboms_to_atlas:
        - uploaded n_sboms to TPA.
        - created a directory for the failed SBOMs and no SBOMs failed
        - created the TPA upload report in the correct file
    """
    sbom_gen = tpa_client.list_sboms(query="", sort="ingested")
    sboms = [sbom async for sbom in sbom_gen]
    assert len(sboms) == n_sboms
    assert (data_dir / failed_sboms_path).exists()
    assert len(os.listdir(failed_sboms_path)) == 0
    assert (data_dir / tpa_report_path).exists()


def verify_generate_upload_report(data_dir: Path, final_report_path: Path) -> None:
    """
    Verify that generate_upload_report executed successfully.
    """
    assert (data_dir / final_report_path).exists()


def run_create_product_sbom(
    data_dir: Path, snapshot_spec: Path, release_data: Path, sbom_path: Path
) -> None:
    """
    Run the create_product_sbom script with the given parameters.
    """
    result = subprocess.run(
        [
            "create_product_sbom",
            "--data-dir",
            data_dir,
            "--snapshot-spec",
            snapshot_spec,
            "--release-data",
            release_data,
            "--sbom-path",
            sbom_path,
        ]
    )

    assert result.returncode == 0


def run_upload_sboms_to_atlas(
    data_dir: Path,
    atlas_api_url: str,
    sbom_path: Path,
    report_path: Path,
    failed_dir: Path,
    auth_env: dict[str, str],
) -> None:
    """
    Run the upload_sboms_to_atlas script with the given parameters.
    """
    env = os.environ.copy()
    env.update(auth_env)

    result = subprocess.run(
        [
            "upload_sboms_to_atlas",
            "--data-dir",
            data_dir,
            "--atlas-api-url",
            atlas_api_url,
            "--sbom-path",
            sbom_path,
            "--report-path",
            report_path,
            "--failed-dir",
            failed_dir,
        ],
        env=env,
    )

    assert result.returncode == 0


def run_upload_sboms_to_s3(
    data_dir: Path, retry_s3_bucket: str, failed_dir: Path, auth_env: dict[str, str]
) -> None:
    """
    Run the upload_sboms_to_s3 script with the given parameters.
    """
    env = os.environ.copy()
    env.update(auth_env)

    result = subprocess.run(
        [
            "upload_sboms_to_s3",
            "--data-dir",
            data_dir,
            "--retry-s3-bucket",
            retry_s3_bucket,
            "--failed-dir",
            failed_dir,
        ],
        env=env,
    )

    assert result.returncode == 0


def run_generate_upload_report(
    data_dir: Path, tpa_report: Path, failed_dir: Path, result: Path, type: str
) -> None:
    """
    Run the generate_upload_report script with the given parameters.
    """
    call_result = subprocess.run(
        [
            "generate_upload_report",
            "--data-dir",
            data_dir,
            "--tpa-report",
            tpa_report,
            "--failed-dir",
            failed_dir,
            "--result",
            result,
            "--type",
            type,
        ]
    )

    assert call_result.returncode == 0
