import json
import random
from pathlib import Path
from typing import Any

import pytest

from mobster.cmd.upload.tpa import TPAClient
from mobster.image import Image
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.utils import run_cmd

TESTDATA_PATH = Path(__file__).parent.parent / "data"


async def create_child_image(
    oci_client: ReferrersTagOCIClient, repository: str, tag: str
) -> Image:
    """
    Create a sample child image in the OCI registry.

    Args:
        oci_client (ReferrersTagOCIClient): A client for interacting with the OCI
        registry.
        repository (str): A name of the repository where the image will be created.
        tag (str): A tag for the image.

    Returns:
        Image: A created image object.
    """
    return await oci_client.create_image(
        repository,
        f"{tag}-child",
    )


async def create_index_image(
    oci_client: ReferrersTagOCIClient, repository: str, tag: str, child_image: Image
) -> Image:
    """
    Create an OCI image index that contains the child image.

    Args:
        oci_client (ReferrersTagOCIClient): A client for interacting with the OCI
        registry.
        repository (str): A name of the repository where the index image will be
        created.
        tag (str): A tag for the index image.
        child_image (Image): A child image to include in the index.

    Returns:
        Image: A created index image object.
    """
    return await oci_client.create_image_index(
        repository,
        f"{tag}-parent",
        images=[child_image],
    )


async def generate_child_image_sbom(child_image: Image, output_dir: Path) -> Path:
    """
    Generate an SBOM for a child image using the `mobster` command-line tool.

    Args:
        child_image (Image): A child image for which the SBOM will be generated.
        output_dir (Path): A directory where the SBOM will be saved.

    Returns:
        Path: A path to the generated SBOM file.
    """
    output_file = output_dir / "oci-image.spdx.json"
    await run_cmd(
        [
            "mobster",
            "generate",
            "--output",
            str(output_file),
            "oci-image",
            "--from-syft",
            str(TESTDATA_PATH / "integration" / "image.syft.spdx.json"),
            "--image-digest",
            child_image.digest,
            "--image-pullspec",
            f"{child_image.repository}:{child_image.tag}",
        ],
    )
    return output_file


async def generate_index_image_sbom(index_image: Image, output_dir: Path) -> Path:
    """
    Generate an SBOM for an OCI image index using the `mobster` command-line tool.

    Args:
        index_image (Image): An index image for which the SBOM will be generated.
        output_dir (Path): A directory where the SBOM will be saved.

    Returns:
        Path: A path to the generated SBOM file.
    """
    index_manifest_path = output_dir / "index-manifest.json"
    with open(index_manifest_path, "w", encoding="utf-8") as file:
        file.write(index_image.manifest or "")

    output_file = output_dir / "oci-index.spdx.json"
    await run_cmd(
        [
            "mobster",
            "generate",
            "--output",
            str(output_file),
            "oci-index",
            "--index-image-digest",
            index_image.digest,
            "--index-image-pullspec",
            f"{index_image.repository}:{index_image.tag}",
            "--index-manifest-path",
            str(index_manifest_path),
        ],
    )
    return output_file


def _get_document_describes_package(document: dict[str, Any]) -> Any:
    """
    Find the package in the SBOM document that describes the SBOM itself.

    Args:
        document (dict): An SPDX document SBOM object.

    Returns:
        Any: A package object that describes the SBOM itself.
    """
    for relationship in document.get("relationships", []):
        if (
            relationship["relationshipType"] == "DESCRIBES"
            and relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
        ):
            package_spdx_id = relationship["relatedSpdxElement"]
            break
    else:
        raise ValueError("Child SBOM does not contain a valid SPDX ID")

    for package in document.get("packages", []):
        if package["SPDXID"] == package_spdx_id:
            return package

    raise ValueError(
        f"SBOM is missing a package with the specified SPDX ID {package_spdx_id}"
    )


def _get_pkg_purls(package: dict[str, Any]) -> list[str]:
    """
    Get all PURLs from the package's external references.

    Args:
        package (dict): A spdx package dictionary.

    Returns:
        list[str]: A list of PURLs found in the package's external references.
    """
    refs = package.get("externalRefs", [])
    return [item["referenceLocator"] for item in refs]


def is_main_package_present_in_other_sbom(
    sbom_with_main_pkg_path: Path,
    other_sbom_path: Path,
    all_purl_match: bool,
) -> bool:
    """
    Check if and package that DESCRIBES the first SBOM is present in the other SBOM.
    The comparison is done based on PURLs in the external references of the packages.

    Args:
        sbom_with_main_pkg_path (Path): A path to the SBOM that contains the main
        package.
        other_sbom_path (Path): A path to the SBOM that is checked for the presence
        of the main package.
        all_purl_match (bool): A flag indicating whether all PURLs must match or
        if any PURL match is sufficient.

    Returns:
        bool: A boolean indicating whether the main package is present in the
        other SBOM.
    """
    with open(sbom_with_main_pkg_path, encoding="utf-8") as sbom_with_main_pkg_file:
        sbom_with_main_pkg = json.load(sbom_with_main_pkg_file)

    with open(other_sbom_path, encoding="utf-8") as other_sbom_file:
        other_sbom = json.load(other_sbom_file)

    # Get the main package from the SBOM that describes it
    # and extract its PURLs.
    main_pkg = _get_document_describes_package(sbom_with_main_pkg)
    main_pkg_purls = _get_pkg_purls(main_pkg)

    # Iterate through the packages in the other SBOM and check for matches.
    for package in other_sbom.get("packages", []):
        child_purls_in_index = _get_pkg_purls(package)

        if all_purl_match:
            if set(main_pkg_purls) == set(child_purls_in_index):
                return True
        else:
            # Check if any of the child PURLs are present in the index PURLs
            # This allows for partial matches, which is useful for cases where
            # the child image may have additional PURLs not present in the index.
            if set(main_pkg_purls) & set(child_purls_in_index):
                return True
    return False


async def augment_oci_image(snapshot_path: Path, output_dir: Path) -> None:
    """
    Augment images generated from the snapshot using the `mobster` command-line tool.

    Args:
        snapshot_path (Path): A path to the snapshot file that contains the images
        output_dir (Path): A directory where the augmented image SBOMs will be saved.

    """
    await run_cmd(
        [
            "mobster",
            "augment",
            "--output",
            str(output_dir),
            "oci-image",
            "--snapshot",
            str(snapshot_path),
        ],
    )


async def generate_product_sbom(
    release_data: Path, snapshot_path: Path, output_dir: Path
) -> Path:
    """
    Generate a product SBOM using the `mobster` command-line tool.

    Args:
        release_data (Path): A path to the release data file that contains
        information about the release.
        snapshot_path (Path): A path to the snapshot file that contains the images
        references for the release.
        output_dir (Path): An output directory where the product SBOM will be saved.

    Returns:
        Path: A path to the generated product SBOM file.
    """
    sbom_file = output_dir / "product.spdx.json"
    await run_cmd(
        [
            "mobster",
            "generate",
            "--output",
            str(sbom_file),
            "product",
            "--release-data",
            str(release_data),
            "--snapshot",
            str(snapshot_path),
        ],
    )
    return sbom_file


def generate_and_store_snapshot(index_image: Image, output_dir: Path) -> Path:
    """
    Generate a snapshot file for the index image and store it in the specified
    output directory.

    Args:
        index_image (Image): An index image for which the snapshot will be generated.
        output_dir (Path): A directory where the snapshot will be saved.

    Returns:
        Path: A path to the generated snapshot file.
    """
    content = {
        "components": [
            {
                "name": index_image.name,
                "containerImage": index_image.reference,
                "rh-registry-repo": "registry.redhat.io/sample/test-repo",
                "repository": index_image.repository,
                "tags": ["1.0", "latest"],
            }
        ]
    }
    snapshot_file = output_dir / "snapshot.json"
    with open(snapshot_file, "w", encoding="utf-8") as file:
        json.dump(content, file, indent=2)
    return snapshot_file


@pytest.mark.asyncio
async def test_consistent_reference(
    tpa_client: TPAClient,
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
) -> None:
    """
    Test that generates SBOMs for a child image and an index image, augment
    them in the "release" phase and generates a product SBOM that
    references the augmented index image.

    The test checks that the SBOMs are connected using purls and have right
    hierarchy.

    Rules that are checked:
     - Index image contains a child image
     - Augmented index image contains a child image
     - Product SBOM contains an augmented index image
     - All SBOMs are uploaded to TPA successfully

    Args:
        tpa_client (TPAClient): A client for interacting with the TPA API.
        oci_client (ReferrersTagOCIClient): A client for interacting with the OCI
        registry.
        tmp_path (Path): A temporary directory for storing generated files.
    """

    tag_prefix = f"{random.randint(100, 9999)}"
    repository = "test-repo"

    child_image = await create_child_image(oci_client, repository, tag_prefix)
    index_image = await create_index_image(
        oci_client,
        repository,
        tag_prefix,
        child_image,
    )
    child_sbom = await generate_child_image_sbom(child_image, tmp_path)
    index_sbom = await generate_index_image_sbom(index_image, tmp_path)

    assert is_main_package_present_in_other_sbom(
        child_sbom, index_sbom, True
    ), "Child image SBOM is not referenced in the index SBOM"

    await oci_client.attach_sbom(child_image, "spdx", child_sbom.read_bytes())
    await oci_client.attach_sbom(index_image, "spdx", index_sbom.read_bytes())

    snapshot_path = generate_and_store_snapshot(index_image, tmp_path)

    await augment_oci_image(snapshot_path, tmp_path)

    assert is_main_package_present_in_other_sbom(
        tmp_path / child_image.digest,
        tmp_path / index_image.digest,
        True,
    ), "Child image SBOM is not referenced in the augmented index SBOM"

    product_sbom_path = await generate_product_sbom(
        TESTDATA_PATH / "integration" / "consistency_check_release_data.json",
        snapshot_path,
        tmp_path,
    )

    assert is_main_package_present_in_other_sbom(
        tmp_path / index_image.digest, product_sbom_path, True
    ), "Product SBOM doesn't contain an augmented index image"

    sboms_to_upload = [
        # original SBOMs
        child_sbom,
        index_sbom,
        # augmented SBOMs
        tmp_path / child_image.digest,
        tmp_path / index_image.digest,
        # product SBOM
        product_sbom_path,
    ]
    for sbom in sboms_to_upload:
        assert sbom.exists(), f"SBOM file {sbom} does not exist"
        await tpa_client.upload_sbom(sbom)
