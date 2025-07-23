"""
This module contains integration tests for scripts used in release Tekton
tasks.
"""

import json
import subprocess
from pathlib import Path
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_lazy_fixtures import lf

from mobster.cmd.generate.oci_index import GenerateOciIndexCommand
from mobster.cmd.upload.tpa import TPAClient
from mobster.tekton.common import AtlasTransientError, upload_sboms
from mobster.tekton.s3 import S3Client
from tests.conftest import GenerateOciImageTestCase
from tests.integration.oci_client import ReferrersTagOCIClient


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


@pytest.mark.asyncio
@patch("mobster.tekton.common.upload_to_atlas", autospec=True)
async def test_sbom_upload_fallback(
    mock_upload_to_atlas: AsyncMock,
    tmp_path: Path,
    tpa_base_url: str,
    tpa_auth_env: dict[str, str],
    s3_client: S3Client,
    s3_sbom_bucket: str,
    s3_auth_env: dict[str, str],
):
    """
    Verify that when the Atlas upload fails with a transient error, the
    fallback mechanism is run and the SBOM is uploaded to S3 instead.
    """
    key = "test_file.json"
    test_data = {"test": "data"}
    file_path = tmp_path / key
    with open(file_path, "w") as f:
        json.dump(test_data, f)

    # mock the atlas upload to raise a transient error
    mock_upload_to_atlas.side_effect = AtlasTransientError
    await upload_sboms(tmp_path, tpa_base_url, s3_sbom_bucket)

    # check that the fallback to s3 uploaded the object
    assert await s3_client.exists(key) is True


async def get_oci_index_sbom(manifest_path: Path, pullspec: str, digest: str) -> bytes:
    args = MagicMock()
    args.index_manifest_path = manifest_path
    args.index_image_pullspec = pullspec
    args.index_image_digest = digest

    with tempfile.NamedTemporaryFile("w+b", suffix=".json") as fp:
        args.output = fp.name

        command = GenerateOciIndexCommand(args)
        await command.execute()
        await command.save()
        fp.flush()
        return fp.read()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "generate_oci_image_case",
    [
        lf("test_case_spdx_with_hermeto_and_additional"),
        lf("test_case_spdx_without_hermeto_without_additional"),
        lf("test_case_spdx_multiple_syft"),
        lf("test_case_cyclonedx_with_additional"),
    ],
)
async def test_process_component_sboms_happypath(
    generate_oci_image_case: GenerateOciImageTestCase,
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

    repo_name = "release"
    image = await oci_client.create_image(repo_name, "latest")
    index = await oci_client.create_image_index(
        repo_name, "latest-index", images=[image]
    )

    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    manifest_path = manifest_dir / "manifest.json"
    with open(manifest_path, "w") as fp:
        assert index.manifest is not None
        obj = json.loads(index.manifest)
        json.dump(obj, fp)

    index_sbom = await get_oci_index_sbom(
        manifest_path,
        f"{registry_url.removeprefix('http://')}/{repo_name}:latest-index",
        digest=index.digest,
    )
    await oci_client.attach_sbom(index, "spdx", index_sbom)

    repo = f"{registry_url.removeprefix('http://')}/{repo_name}"
    snapshot = {
        "components": [
            {
                "name": "component",
                "containerImage": f"{repo}@{index.digest}",
                "rh-registry-repo": "registry.redhat.io/test",
                "tags": ["latest", "1.0"],
                "repository": repo,
            }
        ]
    }

    with open(generate_oci_image_case.expected_sbom_path) as fp:
        # TODO: make a reusable function out of this
        sbom = fp.read()
        sbom = sbom.replace(generate_oci_image_case.args.image_digest, image.digest)
        sbom = sbom.replace(
            generate_oci_image_case.args.image_digest.removeprefix("sha256:"),
            image.digest.removeprefix("sha256:"),
        )
        sbom_bytes = sbom.encode()

    await oci_client.attach_sbom(image, "spdx", sbom_bytes)

    with open(data_dir / snapshot_path, "w") as fp:
        json.dump(snapshot, fp)

    subprocess.run(
        [
            "process_component_sboms",
            "--data-dir",
            data_dir,
            "--snapshot-spec",
            snapshot_path,
            "--atlas-api-url",
            tpa_base_url,
            "--retry-s3-bucket",
            s3_sbom_bucket,
        ],
        check=True,
    )

    assert set((data_dir / "sbom").iterdir()) == {
        data_dir / "sbom" / image.digest,
        data_dir / "sbom" / index.digest,
    }

    await verify_sboms_in_tpa(tpa_client, n_sboms=2)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_bucket_empty() is True
