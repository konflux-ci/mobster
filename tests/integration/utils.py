"""Utility functions for integration tests."""

import json
from pathlib import Path
from typing import Any

from mobster.cmd.upload.tpa import TPAClient


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


async def upload_test_sbom(tpa_client: TPAClient, sbom_path: Path) -> None:
    """
    Upload a test SBOM and verify it was successful.

    Args:
        tpa_client: The TPA client to use for upload
        sbom_path: Path to the SBOM file to upload
    """
    response = await tpa_client.upload_sbom(sbom_path)
    assert response.status_code == 201, f"Upload failed: {response.text}"
