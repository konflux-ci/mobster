"""Utility functions for integration tests."""

import json
import tempfile
from pathlib import Path
from typing import Any

from mobster.image import Image
from mobster.oci.cosign.static import StaticKeySigner
from mobster.sbom.detect import BOMFormat


def prepare_input_sbom(
    source_file: Path, destination_dir: Path, dest_filename: str, sbom_name: str
) -> tuple[Path, Any]:
    """
    A utility function to prepare an input SBOM file for testing.
    It changes the name of the SBOM in the JSON file and saves it to a specified
    destination.

    Args:
        source_file (Path): A path to the source SBOM file.
        destination_dir (Path): A directory where the modified SBOM will be saved.
        dest_filename (str): A filename for the modified SBOM file.
        sbom_name (str): A name to set in the SBOM JSON content.

    Returns:
        tuple[Path, Any]: A tuple containing the path to the modified SBOM file
        and its content.
    """
    with open(source_file, encoding="utf-8") as file:
        original_content = json.load(file)

    dest_path = destination_dir / dest_filename
    original_content["name"] = sbom_name
    with open(dest_path, "w", encoding="utf-8") as file:
        json.dump(original_content, file)

    return dest_path, original_content


async def attest_sbom_bytes(
    signer: StaticKeySigner, image: Image, sbom: bytes, sbom_format: BOMFormat
) -> None:
    """
    Sign an in-memory SBOM and attach it to an image as a cosign attestation.

    Args:
        signer: Signer holding the key used to sign the attestation.
        image: Image to attest.
        sbom: Raw SBOM content.
        sbom_format: Format of the SBOM, which selects the attestation type.
    """
    with tempfile.NamedTemporaryFile() as sbom_file:
        sbom_file.write(sbom)
        sbom_file.flush()
        await signer.attest_sbom(Path(sbom_file.name), image.reference, sbom_format)
