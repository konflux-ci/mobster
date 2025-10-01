import json
import random
from pathlib import Path
from typing import Any

import pytest
import yaml

from mobster.image import Image
from mobster.utils import run_async_subprocess
from tests.integration import img_utils
from tests.integration.oci_client import ReferrersTagOCIClient

TESTDATA_PATH = Path(__file__).parent.parent / "data"


async def generate_key_pair(tmp_path: Path) -> tuple[Path, Path]:
    """
    Generate a public/private key pair for signing attestation.

    Args:
        tmp_path (Path): A temporary directory path to store the keys.

    Returns:
        tuple[Path, Path]: Paths to the private and public keys.

    """

    code, _, stderr = await run_async_subprocess(
        [
            "cosign",
            "generate-key-pair",
        ],
        env={"COSIGN_PASSWORD": ""},
        cwd=tmp_path,
    )
    if code != 0:
        raise RuntimeError(
            f"Failed to generate keypar using cosign.Error: {stderr.decode()}"
        )
    return tmp_path / "cosign.key", tmp_path / "cosign.pub"


def update_index_image_step(
    task: dict[str, Any], index_img: Image, child_img: Image, index_sbom_ref: str
) -> None:
    """
    Update attestation result of index image build step with actual image details.

    Args:
        task (dict[str, Any]): A index image build task from attestation data.
        index_img (Image): A created index image object.
        child_img (Image): A created child image object.
        index_sbom_ref (str): A reference of the index image SBOM.
    """
    for result in task.get("results", []):
        if result.get("name") == "IMAGES":
            result["value"] = f"{child_img.repository}@{child_img.digest}"
        if result.get("name") == "IMAGE_DIGEST":
            result["value"] = index_img.digest
        if result.get("name") == "IMAGE_REF":
            result["value"] = f"{index_img.repository}@{index_img.digest}"
        if result.get("name") == "IMAGE_URL":
            result["value"] = f"{index_img.repository}:{index_img.tag}"
        if result.get("name") == "SBOM_BLOB_URL":
            result["value"] = index_sbom_ref


def update_child_image_step(
    task: dict[str, Any], child_img: Image, child_sbom_ref: str
) -> None:
    """
    Update attestation result of child image build step with actual image details.

    Args:
        task (dict[str, Any]): A child image build task from attestation data.
        child_img (Image): A created child image object.
        child_sbom_digest (str): A reference of the child image SBOM.
    """
    for result in task.get("results", []):
        if result.get("name") == "IMAGE_DIGEST":
            result["value"] = child_img.digest
        if result.get("name") == "IMAGE_REF":
            result["value"] = f"{child_img.repository}@{child_img.digest}"
        if result.get("name") == "IMAGE_URL":
            result["value"] = f"{child_img.repository}:{child_img.tag}"
        if result.get("name") == "SBOM_BLOB_URL":
            result["value"] = child_sbom_ref


def update_attestation_with_image_details(
    attestation_data: dict[str, Any],
    index_img: Image,
    child_img: Image,
    index_sbom_ref: str,
    child_sbom_ref: str,
) -> None:
    """
    Inject image details into attestation data to match with pushed images.

    Args:
        attestation_data (dict[str, Any]): Attestation data template.
        index_img (Image): Index image to inject details for.
        child_img (Image): Child image to inject details for.
        index_sbom_ref (str): Index SBOM reference
        child_sbom_ref (str): Child SBOM reference.

    """

    tasks = attestation_data.get("buildConfig", {}).get("tasks", [])
    for task in tasks:
        if task.get("name") == "build-image-index":
            update_index_image_step(task, index_img, child_img, index_sbom_ref)
        if task.get("name") == "build-images":
            update_child_image_step(task, child_img, child_sbom_ref)


async def create_image_attestation(
    oci_client: ReferrersTagOCIClient,
    index_img: Image,
    child_img: Image,
    index_sbom_ref: str,
    child_sbom_ref: str,
    private_key_path: Path,
    tmp_path: Path,
) -> None:
    """
    Create attestation with data matching the pushed images and upload it to the
    OCI registry as signed attestation associated with both images.

    Args:
        oci_client (ReferrersTagOCIClient): Registry client to use for uploading
            the attestation.
        index_img (Image): Index image to associate the attestation with.
        child_img (Image): Child image to associate the attestation with.
        index_sbom_ref (str): Index SBOM reference.
        child_sbom_ref (str): Child SBOM reference.
        private_key_path (Path): A path to the private key for signing the
            attestation.
        tmp_path (Path): A temporary directory path to store the attestation file.
    """
    attestatuon_template_path = TESTDATA_PATH / "integration" / "img_attestation.json"
    with open(attestatuon_template_path, encoding="utf-8") as attestation_file:
        attestation_data = json.load(attestation_file)["predicate"]

    update_attestation_with_image_details(
        attestation_data, index_img, child_img, index_sbom_ref, child_sbom_ref
    )

    # Write the updated attestation to a temporary file
    attestatuon_path = tmp_path / "img_attestation.json"
    with open(attestatuon_path, "w", encoding="utf-8") as attestation_file:
        json.dump(attestation_data, attestation_file, indent=2)

    await oci_client.push_attestation(
        child_img, attestatuon_path, "slsaprovenance02", private_key_path
    )
    await oci_client.push_attestation(
        index_img, attestatuon_path, "slsaprovenance02", private_key_path
    )


def create_policy_file(policy_dir_path: Path) -> Path:
    """
    Create a Conforma policy file in the specified directory with SBOM related
    checks enabled.
    Args:
        policy_dir_path (Path): A directory where the policy file will be created.

    Returns:
        Path: A path to the created policy file.
    """
    policy = {
        "sources": [
            {
                "policy": ["github.com/conforma/policy//policy"],
                "config": {
                    # These are the checks that will be run by Conforma
                    # and are relevant for SBOM validation.
                    "include": [
                        "sbom",
                        "sbom_spdx",
                        "sbom_cyclonedx",
                        "rpm_repos",
                        "base_image_registries",
                    ]
                },
                "data": ["git::https://github.com/conforma/policy//example/data"],
            }
        ]
    }
    policy_path = policy_dir_path / "policy.json"
    with open(policy_path, "w", encoding="utf-8") as policy_file:
        yaml.safe_dump(policy, policy_file)
    return policy_path


async def verify_conforma(image: Image, public_key: Path, tmp_path: Path) -> None:
    """
    Validate a conforma rules agains a provided image.

    Args:
        image (Image): An image to validate.
        public_key (Path): A path to the public key for verifying the attestation.
        tmp_path (Path): A temporary directory path to store the policy file.

    """
    policy_file_path = create_policy_file(tmp_path)
    cmd = [
        "ec",
        "validate",
        "image",
        "--policy",
        str(policy_file_path),
        "--public-key",
        str(public_key),
        "--ignore-rekor",
        "--image",
        f"{image.repository}@{image.digest}",
    ]
    code, stdout, stderr = await run_async_subprocess(cmd)
    if code != 0:
        raise RuntimeError(
            f"Failed to run conforma:\n"
            f"CMD: {' '.join(cmd)}\n"
            f"Error: {stderr.decode()}\n"
            f"Output: {stdout.decode()}"
        )


@pytest.mark.asyncio
async def test_oci_image_sboms_using_conforma(
    oci_client: ReferrersTagOCIClient, tmp_path: Path
) -> None:
    """
    Verify that SBOMs generated by Mobster for OCI images can be validated
    using Conforma and don't trigger any policy violations.

    Args:
        oci_client (ReferrersTagOCIClient): A registry client to use for pushing
            and pulling images and associated artifacts.
        tmp_path (Path): A temporary directory path to store generated files.
    """
    tag_prefix = f"{random.randint(100, 9999)}"
    repository = "test-repo"

    private_key_path, public_key_path = await generate_key_pair(tmp_path)

    child_image = await img_utils.create_child_image(oci_client, repository, tag_prefix)
    index_image = await img_utils.create_index_image(
        oci_client,
        repository,
        tag_prefix,
        child_image,
    )

    await oci_client.sign_image(index_image, private_key_path)
    await oci_client.sign_image(child_image, private_key_path)

    child_sbom = await img_utils.generate_child_image_sbom(child_image, tmp_path)
    index_sbom = await img_utils.generate_index_image_sbom(index_image, tmp_path)

    child_sbom_ref = await oci_client.attach_sbom(
        child_image, "spdx", child_sbom.read_bytes()
    )
    index_sbom_ref = await oci_client.attach_sbom(
        index_image, "spdx", index_sbom.read_bytes()
    )

    await create_image_attestation(
        oci_client,
        index_image,
        child_image,
        index_sbom_ref,
        child_sbom_ref,
        private_key_path,
        tmp_path,
    )

    await verify_conforma(index_image, public_key_path, tmp_path)
    await verify_conforma(child_image, public_key_path, tmp_path)
