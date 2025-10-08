"""
This module contains integration tests for scripts used in release Tekton
tasks.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_lazy_fixtures import lf

from mobster.cmd.generate.oci_index import GenerateOciIndexCommand
from mobster.cmd.generate.product import ReleaseNotes
from mobster.cmd.upload.tpa import TPAClient
from mobster.cmd.upload.upload import (
    TPAUploadCommand,
    TPAUploadFailure,
    TPAUploadReport,
    UploadConfig,
)
from mobster.image import Image
from mobster.oci.artifact import Provenance02, SBOMFormat
from mobster.oci.cosign import Cosign, CosignClient, CosignConfig
from mobster.release import ReleaseId
from mobster.tekton.artifact import (
    COMPONENT_ARTIFACT_NAME,
    PRODUCT_ARTIFACT_NAME,
    ProductArtifact,
    SBOMArtifact,
)
from mobster.tekton.common import upload_sboms
from mobster.tekton.s3 import S3Client
from tests.cmd.generate.test_product import verify_product_sbom
from tests.conftest import GenerateOciImageTestCase
from tests.integration.oci_client import ReferrersTagOCIClient

TESTDATA_PATH = Path(__file__).parent.parent / "data"


@pytest.fixture(scope="session")
def cosign_client_with_keys(
    cosign_sign_key: Path, cosign_verify_key: Path
) -> CosignClient:
    return CosignClient(
        cosign_config=CosignConfig(
            verify_key=cosign_verify_key, sign_key=cosign_sign_key
        )
    )


async def verify_sboms_in_tpa(
    tpa_client: TPAClient,
    test_id: str,
    artifact: SBOMArtifact,
    n_sboms: int,
) -> None:
    """
    Verify that the SBOMs in the artifact exist in TPA.
    """
    urn_set = set()
    sboms = artifact.sboms
    if isinstance(sboms, ProductArtifact):
        urls = sboms.product
    else:
        urls = sboms.component

    assert len(urls) == n_sboms, (
        "The number of URLs in the artifact doesn't match the expected count."
    )
    for url in urls:
        urn = url.split("/")[-1]
        urn_set.add(urn)

    sbom_gen = tpa_client.list_sboms(query=f"labels:test_id={test_id}", sort="ingested")
    async for sbom in sbom_gen:
        urn_set.remove(sbom.id)

    assert len(urn_set) == 0, f"URNs of SBOMs not found in TPA: {urn_set}"


async def add_provenance_to_sbom(
    cosign_client: Cosign, sbom_ref: str, image: Image
) -> None:
    """
    Push a signed Provenance to an image registry to be able to verify SBOM integrity.
    Args:
        cosign_client: The client used to sign and push the Provenance
        sbom_ref: Reference to the SBOM in the format
            <url>:<tag>.sbom@sha256<digest>
        image: The image which the SBOM and the Provenance belong to

    Returns:
        None
    """
    provenance = Provenance02(
        {
            "builder": {"id": "https://konflux.dev"},
            "buildType": "https://mobyproject.org/buildkit@v1",
            "buildConfig": {
                "tasks": [
                    {
                        "finishedOn": "1970-01-01T00:00:00Z",
                        "results": [
                            {
                                "name": "SBOM_BLOB_URL",
                                "value": sbom_ref,
                            },
                            {"name": "IMAGE_DIGEST", "value": image.digest},
                        ],
                    }
                ]
            },
        }
    )
    await cosign_client.attest_provenance(provenance, image.reference)


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
    result_dir = tmp_path / "results"
    result_dir.mkdir()
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
                "repositories": [
                    {
                        "rh-registry-repo": "registry.redhat.io/test",
                        "tags": ["latest"],
                        "url": "registry.redhat.io/test",
                    },
                    {
                        "rh-registry-repo": "registry.redhat.io/anothertest",
                        "tags": ["latest"],
                        "url": "registry.redhat.io/anothertest",
                    },
                ],
            }
        ]
    }
    expected_purls = [
        f"pkg:oci/test@{image.digest}?repository_url=registry.redhat.io/test&tag=latest",
        f"pkg:oci/anothertest@{image.digest}?repository_url=registry.redhat.io/anothertest&tag=latest",
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

    sbom_path = tmp_path / "sbom.json"
    subprocess.run(
        [
            "process_product_sbom",
            "--data-dir",
            data_dir,
            "--result-dir",
            result_dir,
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
            "--concurrency",
            str(product_concurrency),
            "--labels",
            f"test_id={test_id}",
            "--sbom-path",
            str(sbom_path),
        ],
        check=True,
    )

    # check that an SBOM was created and contains what is expected
    with open(sbom_path) as fp:
        sbom_dict = json.load(fp)
        verify_product_sbom(
            sbom_dict,
            [str(component["name"]) for component in snapshot["components"]],
            ReleaseNotes.model_validate_json(json.dumps(release_data["releaseNotes"])),
            expected_purls,
            release_id,
        )

    artifact_path = result_dir / PRODUCT_ARTIFACT_NAME
    assert artifact_path.exists()
    with open(artifact_path) as fp:
        artifact = SBOMArtifact.model_validate_json(fp.read())

    await verify_sboms_in_tpa(tpa_client, test_id, artifact, n_sboms=1)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_prefix_empty("/")

    # check that regeneration data was pushed
    assert await s3_client.snapshot_exists(release_id)
    assert await s3_client.release_data_exists(release_id)


@pytest.mark.asyncio
@patch("mobster.cmd.upload.upload.TPAUploadCommand.upload", autospec=True)
async def test_sbom_upload_fallback(
    mock_tpa_upload: AsyncMock,
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

    mock_tpa_upload.return_value = TPAUploadReport(
        success=[],
        failure=[
            TPAUploadFailure(path=file_path, transient=True, message="Transient error")
        ],
    )
    auth = TPAUploadCommand.get_oidc_auth()
    await upload_sboms(
        UploadConfig(
            auth=auth,
            base_url=tpa_base_url,
            labels={},
            retries=1,
            workers=1,
        ),
        s3_client,
        paths=[file_path],
    )

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
    cosign: CosignClient | None = None,
) -> Image:
    """
    Create an image and attach an SBOM sourced from the expected sbom of a
    GenerateOciImageTestCase object.
    """
    image = await oci_client.create_image(repo, "latest")
    sbom = get_sbom_from_test_case(case, image.digest)
    sbom_ref = await oci_client.attach_sbom(image, "spdx", sbom)
    if cosign:
        await add_provenance_to_sbom(cosign, sbom_ref, image)
    return image


async def create_index_with_build_sbom(
    oci_client: ReferrersTagOCIClient,
    repo_with_registry: str,
    repo: str,
    images: list[Image],
    tmp_path: Path,
    cosign: CosignClient | None = None,
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

    sbom_ref = await oci_client.attach_sbom(index, "spdx", sbom)
    if cosign:
        await add_provenance_to_sbom(cosign, sbom_ref, index)
    return index


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["generate_oci_image_case", "image_sbom_type"],
    [
        (lf("test_case_spdx_with_hermeto_and_additional"), SBOMFormat.SPDX_2_3),
        (lf("test_case_spdx_without_hermeto_without_additional"), SBOMFormat.SPDX_2_3),
        (lf("test_case_spdx_multiple_syft"), SBOMFormat.SPDX_2_3),
        (lf("test_case_cyclonedx_with_additional"), SBOMFormat.CDX_V1_6),
    ],
)
async def test_process_component_sboms_happypath(
    test_id: str,
    generate_oci_image_case: GenerateOciImageTestCase,
    image_sbom_type: SBOMFormat,
    s3_client: S3Client,
    s3_sbom_bucket: str,
    tpa_client: TPAClient,
    tpa_base_url: str,
    oci_client: ReferrersTagOCIClient,
    registry_url: str,
    tmp_path: Path,
    augment_concurrency: int,
    upload_concurrency: int,
    attestation_concurrency: int,
    cosign_sign_key: Path,
    cosign_verify_key: Path,
    cosign_client_with_keys: CosignClient,
) -> None:
    """
    Create an image and an index with build-time SBOMs, run the augmentation
    and verify results.
    """
    data_dir = tmp_path
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    snapshot_path = Path("snapshot.json")
    release_id = ReleaseId.new()

    repo_name = "release"
    registry = registry_url.removeprefix("http://")
    repo_with_registry = f"{registry}/{repo_name}"
    image = await create_image_with_build_sbom(
        oci_client, generate_oci_image_case, repo_name, cosign_client_with_keys
    )
    index = await create_index_with_build_sbom(
        oci_client,
        repo_with_registry,
        repo_name,
        [image],
        tmp_path,
        cosign_client_with_keys,
    )

    snapshot: dict[str, Any] = {
        "components": [
            {
                "name": "component",
                "containerImage": f"{repo_with_registry}@{index.digest}",
                "rh-registry-repo": f"{registry}/test",
                "tags": ["latest", "1.0"],
                "repositories": [
                    {
                        "rh-registry-repo": "registry.redhat.io/test",
                        "url": f"{registry}/test",
                        "tags": ["latest", "1.0"],
                    },
                    {
                        "rh-registry-repo": "registry.redhat.io/anothertest",
                        "url": f"{registry}/anothertest",
                        "tags": ["1.0"],
                    },
                ],
            }
        ]
    }

    with open(data_dir / snapshot_path, "w") as fp:
        json.dump(snapshot, fp)

    assert not await s3_client.snapshot_exists(release_id)

    subprocess.run(
        [
            "process_component_sboms",
            "--data-dir",
            data_dir,
            "--result-dir",
            result_dir,
            "--snapshot-spec",
            snapshot_path,
            "--atlas-api-url",
            tpa_base_url,
            "--retry-s3-bucket",
            s3_sbom_bucket,
            "--release-id",
            str(release_id),
            "--augment-concurrency",
            str(augment_concurrency),
            "--upload-concurrency",
            str(upload_concurrency),
            "--attest-concurrency",
            str(attestation_concurrency),
            "--sign-key",
            str(cosign_sign_key),
            "--verify-key",
            str(cosign_verify_key),
            "--labels",
            f"test_id={test_id}",
        ],
        check=True,
    )

    artifact_path = result_dir / COMPONENT_ARTIFACT_NAME
    assert artifact_path.exists()
    with open(artifact_path) as fp:
        artifact = SBOMArtifact.model_validate_json(fp.read())

    await verify_sboms_in_tpa(tpa_client, test_id, artifact, n_sboms=4)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_prefix_empty("/")

    # check regeneration data was pushed
    assert await s3_client.snapshot_exists(release_id)

    # check for attested SBOMs
    for image_digest, expected_sbom_type in (
        (image.digest, image_sbom_type),
        (index.digest, SBOMFormat.SPDX_2_3),
    ):
        for release_image_repo in snapshot["components"][0]["repositories"]:
            repo_url = release_image_repo["url"]
            sbom = await cosign_client_with_keys.fetch_attested_sbom(
                Image(repository=repo_url, digest=image_digest),
                expected_sbom_type,
            )
            assert sbom
            assert sbom.format == expected_sbom_type
            # Clean up OCI registry from SBOMs so other tests are not interfered with
            await cosign_client_with_keys.clean(
                Image(repository=repo_url, digest=image_digest).reference
            )


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.fail_slow("10m")
async def test_process_component_sboms_big_release(
    test_id: str,
    s3_client: S3Client,
    s3_sbom_bucket: str,
    tpa_client: TPAClient,
    tpa_base_url: str,
    oci_client: ReferrersTagOCIClient,
    registry_url: str,
    tmp_path: Path,
    augment_concurrency: int,
    upload_concurrency: int,
    attestation_concurrency: int,
    cosign_client_with_keys: CosignClient,
    cosign_sign_key: Path,
    cosign_verify_key: Path,
) -> None:
    """
    Create an image and an index with build-time SBOMs, run the augmentation
    and verify results.
    """
    n_components = 200
    data_dir = tmp_path
    snapshot_path = Path("snapshot.json")
    release_id = ReleaseId.new()
    result_dir = tmp_path / "results"
    result_dir.mkdir()

    repo_name = "release"
    registry = registry_url.removeprefix("http://")
    repo_with_registry = f"{registry}/{repo_name}"

    image = await oci_client.create_image(repo_name, "latest")
    with open(TESTDATA_PATH / "integration" / "rhel_bootc.spdx.json") as fp:
        sbom = fp.read()
        sbom = sbom.replace(
            "10b99add019c5bb363b999c7fea919e042deaaba0f44ae528bac843f4d849f0a",
            image.digest.removeprefix("sha256:"),
        )

    sbom_ref = await oci_client.attach_sbom(image, "spdx", sbom.encode())
    await add_provenance_to_sbom(cosign_client_with_keys, sbom_ref, image)

    index = await create_index_with_build_sbom(
        oci_client,
        repo_with_registry,
        repo_name,
        [image],
        tmp_path,
        cosign_client_with_keys,
    )

    # We assign a unique tag to each component, so that we upload different
    # SBOMs. TPA has trouble when uploading multiple identical large SBOMs
    # concurrently. Based on the number of workers, the final state of TPA
    # after the upload can be different.
    snapshot: Any = {"components": []}
    for i in range(n_components):
        snapshot["components"].append(
            {
                "name": f"component-{i}",
                "containerImage": f"{repo_with_registry}@{index.digest}",
                "rh-registry-repo": f"{registry}/test",
                "tags": [str(i)],
                "repositories": [
                    {
                        "rh-registry-repo": "registry.redhat.io/test",
                        "tags": [str(i)],
                        "url": f"{registry}/test",
                    }
                ],
            }
        )

    with open(data_dir / snapshot_path, "w") as fp:
        json.dump(snapshot, fp)

    assert not await s3_client.snapshot_exists(release_id)

    subprocess.run(
        [
            "process_component_sboms",
            "--data-dir",
            data_dir,
            "--result-dir",
            result_dir,
            "--snapshot-spec",
            snapshot_path,
            "--atlas-api-url",
            tpa_base_url,
            "--retry-s3-bucket",
            s3_sbom_bucket,
            "--release-id",
            str(release_id),
            "--augment-concurrency",
            str(augment_concurrency),
            "--upload-concurrency",
            str(upload_concurrency),
            "--attest-concurrency",
            str(attestation_concurrency),
            "--sign-key",
            str(cosign_sign_key),
            "--verify-key",
            str(cosign_verify_key),
            "--labels",
            f"test_id={test_id}",
        ],
        check=True,
    )
    artifact_path = result_dir / COMPONENT_ARTIFACT_NAME
    assert artifact_path.exists()
    with open(artifact_path) as fp:
        artifact = SBOMArtifact.model_validate_json(fp.read())

    await verify_sboms_in_tpa(tpa_client, test_id, artifact, n_sboms=n_components * 2)

    # check that no SBOMs were added to the bucket (TPA upload succeeded)
    assert await s3_client.is_prefix_empty("/")

    # check regeneration data was pushed
    assert await s3_client.snapshot_exists(release_id)
