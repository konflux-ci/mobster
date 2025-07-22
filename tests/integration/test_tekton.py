"""
This module contains integration tests for scripts used in release Tekton
tasks.
"""

import json
import subprocess
from pathlib import Path

import pytest

from mobster.cmd.upload.tpa import TPAClient
from mobster.tekton.s3 import S3Client
from tests.integration.oci_client import ReferrersTagOCIClient


@pytest.mark.asyncio
async def test_create_product_sboms_ta_happypath(
    s3_client: S3Client,
    s3_sbom_bucket: str,
    tpa_client: TPAClient,
    tpa_base_url: str,
    oci_client: ReferrersTagOCIClient,
    registry_url: str,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path
    snapshot_path = Path("snapshot.json")
    release_data_path = Path("data.json")

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

    with open(data_dir / release_data_path, "w") as fp:
        json.dump(release_data, fp)

    subprocess.run(
        [
            "process_product_sbom",
            "--data-dir",
            data_dir,
            "--snapshot-spec",
            snapshot_path,
            "--release-data",
            release_data_path,
            "--atlas-api-url",
            tpa_base_url,
            "--retry-s3-bucket",
            s3_sbom_bucket,
        ],
        check=True,
    )

    # check that an SBOM was created in the expected path
    assert (data_dir / "sbom" / "sbom.json").exists()

    await verify_sboms_in_tpa(tpa_client, n_sboms=1)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_bucket_empty() is True


async def verify_sboms_in_tpa(
    tpa_client: TPAClient,
    n_sboms: int,
) -> None:
    """
    Verify that n_sboms were uploaded to TPA.
    """
    sbom_gen = tpa_client.list_sboms(query="", sort="ingested")
    sboms = [sbom async for sbom in sbom_gen]
    assert len(sboms) == n_sboms


def verify_generate_upload_report(data_dir: Path, final_report_path: Path) -> None:
    """
    Verify that generate_upload_report executed successfully.
    """
    assert (data_dir / final_report_path).exists()
