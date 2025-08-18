"""
This module contains integration tests for scripts used in release Tekton
tasks.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_lazy_fixtures import lf

from mobster.cmd.generate.oci_index import GenerateOciIndexCommand
from mobster.cmd.generate.product import ReleaseNotes
from mobster.cmd.upload.tpa import TPAClient
from mobster.image import Image
from mobster.release import ReleaseId
from mobster.tekton.common import AtlasTransientError, upload_sboms
from mobster.tekton.s3 import S3Client
from tests.cmd.generate.test_product import verify_product_sbom
from tests.conftest import GenerateOciImageTestCase
from tests.integration.oci_client import ReferrersTagOCIClient

CONCURRENCY = 8


async def verify_sboms_in_tpa(
    tpa_client: TPAClient,
    digests: list[str],
    test_id: str,
) -> None:
    """
    Verify that n_sboms were uploaded to TPA.
    """
    digest_set = set(digests)
    sbom_gen = tpa_client.list_sboms(query=f"labels:test_id={test_id}", sort="ingested")
    async for sbom in sbom_gen:
        digest_set.remove(sbom.sha256)

    assert len(digest_set) == 0, f"Digests of SBOMs not found in TPA: {digest_set}"


def parse_digests(process_stdout: bytes) -> list[str]:
    """
    Parse SBOM digests from stdout of process_* commands.
    """
    return process_stdout.decode("utf-8").splitlines()


@pytest.mark.asyncio
async def test_create_product_sboms_ta_happypath(
    test_id: str,
    s3_client: S3Client,
    s3_sbom_bucket: str,
    tpa_client: TPAClient,
    tpa_base_url: str,
    oci_client: ReferrersTagOCIClient,
    registry_url: str,
    tmp_path: Path,
    product_concurrency: int,
) -> None:
    data_dir = tmp_path
    snapshot_path = Path("snapshot.json")
    release_data_path = Path("data.json")
    release_id = ReleaseId.new()

    repo_name = "release"
    image = await oci_client.create_image(repo_name, "latest")
    repo_with_registry = f"{registry_url.removeprefix('http://')}/{repo_name}"
    snapshot = {
        "components": [
            {
                "name": "component",
                "containerImage": f"{repo_with_registry}@{image.digest}",
                "rh-registry-repo": "registry.redhat.io/test",
                "tags": ["latest"],
            }
        ]
    }
    expected_purls = [
        f"pkg:oci/test@{image.digest}?repository_url=registry.redhat.io/test&tag=latest"
    ]

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

    assert not await s3_client.snapshot_exists(release_id)
    assert not await s3_client.release_data_exists(release_id)

    result = subprocess.run(
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
            "--release-id",
            str(release_id),
            "--print-digests",
            "--concurrency",
            str(product_concurrency),
            "--labels",
            f"test_id={test_id}",
        ],
        check=True,
        capture_output=True,
    )

    sbom_digests = parse_digests(result.stdout)

    # check that an SBOM was created and contains what is expected
    with open(data_dir / "sbom" / "sbom.json") as fp:
        sbom_dict = json.load(fp)
        verify_product_sbom(
            sbom_dict,
            [str(component["name"]) for component in snapshot["components"]],
            ReleaseNotes.model_validate_json(json.dumps(release_data["releaseNotes"])),
            expected_purls,
            release_id,
        )

    await verify_sboms_in_tpa(tpa_client, sbom_digests, test_id)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_prefix_empty("/")

    # check that regeneration data was pushed
    assert await s3_client.snapshot_exists(release_id)
    assert await s3_client.release_data_exists(release_id)


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
) -> None:
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
    await upload_sboms(tmp_path, tpa_base_url, s3_client, concurrency=1)

    # check that the fallback to s3 uploaded the object
    assert await s3_client.exists(key) is True


async def get_oci_index_sbom(manifest_path: Path, pullspec: str, digest: str) -> bytes:
    """
    Uses the GenerateOciIndexCommand to generate an index sbom.
    """
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


def get_sbom_from_test_case(case: GenerateOciImageTestCase, image_digest: str) -> bytes:
    """
    Load an SBOM from a GenerateOciImageTestCase, replaces digests with
    specified and return it parsed to bytes.
    """
    with open(case.expected_sbom_path) as fp:
        sbom = fp.read()
        sbom = sbom.replace(
            case.args.image_digest.removeprefix("sha256:"),
            image_digest.removeprefix("sha256:"),
        )
        return sbom.encode()


async def create_image_with_build_sbom(
    oci_client: ReferrersTagOCIClient,
    case: GenerateOciImageTestCase,
    repo: str,
) -> Image:
    """
    Create an image and attach an SBOM sourced from the expected sbom of a
    GenerateOciImageTestCase object.
    """
    image = await oci_client.create_image(repo, "latest")
    sbom = get_sbom_from_test_case(case, image.digest)
    await oci_client.attach_sbom(image, "spdx", sbom)
    return image


async def create_index_with_build_sbom(
    oci_client: ReferrersTagOCIClient,
    repo_with_registry: str,
    repo: str,
    images: list[Image],
    tmp_path: Path,
) -> Image:
    """
    Create an index image and attach an SBOM generated by the GenerateOciIndex
    command.
    """
    index = await oci_client.create_image_index(repo, "index", images)

    manifest_dir = tmp_path / "manifests"
    manifest_dir.mkdir()
    manifest_path = manifest_dir / "manifest.json"
    with open(manifest_path, "w") as fp:
        assert index.manifest is not None
        obj = json.loads(index.manifest)
        json.dump(obj, fp)

    sbom = await get_oci_index_sbom(
        manifest_path,
        f"{repo_with_registry}:index",
        digest=index.digest,
    )

    await oci_client.attach_sbom(index, "spdx", sbom)
    return index


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
    test_id: str,
    generate_oci_image_case: GenerateOciImageTestCase,
    s3_client: S3Client,
    s3_sbom_bucket: str,
    tpa_client: TPAClient,
    tpa_base_url: str,
    oci_client: ReferrersTagOCIClient,
    registry_url: str,
    tmp_path: Path,
    augment_concurrency: int,
    upload_concurrency: int,
) -> None:
    """
    Create an image and an index with build-time SBOMs, run the augmentation
    and verify results.
    """
    data_dir = tmp_path
    snapshot_path = Path("snapshot.json")
    release_id = ReleaseId.new()

    repo_name = "release"
    repo_with_registry = f"{registry_url.removeprefix('http://')}/{repo_name}"
    image = await create_image_with_build_sbom(
        oci_client, generate_oci_image_case, repo_name
    )
    index = await create_index_with_build_sbom(
        oci_client, repo_with_registry, repo_name, [image], tmp_path
    )

    snapshot = {
        "components": [
            {
                "name": "component",
                "containerImage": f"{repo_with_registry}@{index.digest}",
                "rh-registry-repo": "registry.redhat.io/test",
                "tags": ["latest", "1.0"],
            }
        ]
    }

    with open(data_dir / snapshot_path, "w") as fp:
        json.dump(snapshot, fp)

    assert not await s3_client.snapshot_exists(release_id)

    result = subprocess.run(
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
            "--release-id",
            str(release_id),
            "--print-digests",
            "--augment-concurrency",
            str(augment_concurrency),
            "--upload-concurrency",
            str(upload_concurrency),
            "--labels",
            f"test_id={test_id}",
        ],
        check=True,
        capture_output=True,
    )
    sbom_digests = parse_digests(result.stdout)

    assert len(list((data_dir / "sbom").iterdir())) == 2

    await verify_sboms_in_tpa(tpa_client, sbom_digests, test_id)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_prefix_empty("/")

    # check regeneration data was pushed
    assert await s3_client.snapshot_exists(release_id)
