from pathlib import Path

import yaml

from mobster.image import Image, IndexImage
from mobster.utils import run_async_subprocess
from tests.integration.oci_client import ReferrersTagOCIClient

TESTDATA_PATH = Path(__file__).parent.parent / "data"


def make_metadata_yaml(
    tmp_path: Path, img: Image, parent_img: Image | None = None
) -> Path:
    metadata = {
        "image": {
            "pullspec": f"{img.repository}:{img.tag}",
            "digest": img.digest,
        },
        "base_images": [],
    }
    if parent_img:
        metadata["base_images"].append(  # type: ignore[attr-defined]
            {
                "pullspec": f"{parent_img.repository}:{parent_img.tag}",
                "digest": parent_img.digest,
            }
        )
    path = tmp_path / f"{img.digest}.metadata.yaml"
    with open(path, "w") as fp:
        fp.write(yaml.dump(metadata))
    return path


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
) -> IndexImage:
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


async def generate_child_image_sbom(child_image: Image, tmp_path: Path) -> Path:
    """
    Generate an SBOM for a child image using the `mobster` command-line tool.

    Args:
        child_image (Image): A child image for which the SBOM will be generated.
        tmp_path (Path): A directory where the SBOM (and other files necessary
        for generating it) will be saved.

    Returns:
        Path: A path to the generated SBOM file.
    """
    output_file = tmp_path / "oci-image.spdx.json"
    metadata_file = make_metadata_yaml(tmp_path, child_image)
    code, _, stderr = await run_async_subprocess(
        [
            "mobster",
            "generate",
            "--output",
            str(output_file),
            "oci-image",
            "--from-syft",
            str(TESTDATA_PATH / "integration" / "image.syft.spdx.json"),
            "--metadata-path",
            str(metadata_file),
        ],
    )
    if code != 0:
        raise RuntimeError(
            f"Failed to generate SBOM for {child_image.repository}:{child_image.tag}. "
            f"Error: {stderr.decode()}"
        )
    return output_file


async def generate_index_image_sbom(index_image: IndexImage, tmp_path: Path) -> Path:
    """
    Generate an SBOM for an OCI image index using the `mobster` command-line tool.

    Args:
        index_image (Image): An index image for which the SBOM will be generated.
        tmp_path (Path): A directory where the SBOM (and other files necessary
        for generating it) will be saved.

    Returns:
        Path: A path to the generated SBOM file.
    """
    index_manifest_path = tmp_path / "index-manifest.json"
    with open(index_manifest_path, "w", encoding="utf-8") as file:
        file.write(index_image.manifest or "")

    output_file = tmp_path / "oci-index.spdx.json"
    code, _, stderr = await run_async_subprocess(
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
    if code != 0:
        raise RuntimeError(
            f"Failed to generate SBOM for {index_image.repository}:{index_image.tag}. "
            f"Error: {stderr.decode()}"
        )
    return output_file
