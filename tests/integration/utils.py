"""Utility functions for integration tests."""

import asyncio
import json
from pathlib import Path
from typing import Any


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


async def run_cmd(cmd: list[str]) -> str:
    """
    Run a shell command asynchronously and return its output.

    Args:
        cmd (list[str]): A list of command arguments to execute.

    Returns:
        str: A string containing the command's standard output.
    """
    process = await asyncio.create_subprocess_shell(
        " ".join(cmd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(
            f"Command failed with error: {stderr.decode().strip()}",
            f"returncode: {process.returncode}, stdout: {stdout.decode().strip()}",
        )
    return stdout.decode().strip()
