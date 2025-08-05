"""A place for utility functions used across the application."""

import asyncio
import json
import logging
import os
import platform
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)


def normalize_file_name(current_name: str) -> str:
    """
    Normalize a file name by replacing invalid characters with underscores.

    Args:
        current_name (str): The original file name.

    Returns:
        str: The normalized file name.
    """
    return re.sub(r'[<>:"/\\|?*]', "_", current_name)


async def run_async_subprocess(
    cmd: list[str], env: dict[str, str] | None = None, retry_times: int = 0
) -> tuple[int, bytes, bytes]:
    """Run command in subprocess asynchronously.

    Args:
        cmd: Command to run in subprocess.
        env: Environment dictionary.
        retry_times: Number of retries if the process ends with non-zero return code.

    Returns:
        tuple[int, bytes, bytes]: Return code, stdout, and stderr.
    """
    if retry_times < 0:
        raise ValueError("Retry count cannot be negative.")

    cmd_env = dict(os.environ)
    if env:
        cmd_env.update(env)

    # do this to avoid unbound warnings,
    # the loop always runs at least once, so they're always set
    code, stdout, stderr = 0, b"", b""

    for _ in range(1 + retry_times):
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=cmd_env,
        )

        stdout, stderr = await proc.communicate()
        assert (
            proc.returncode is not None
        )  # can't be None after proc.communicate is awaited
        code = proc.returncode
        if code == 0:
            return code, stdout, stderr

    return code, stdout, stderr


def identify_arch() -> str:
    """
    Fetches the runtime arch and converts it to oci manifest arch format.

    Returns:
        oci manifest compatible arch identifier.
    """

    platform_arch = platform.machine()

    arch_translation_map = {
        "amd64": {"x86_64", "x64"},
        "arm64": {"arm", "arm64", "aarch64_be", "aarch64", "armv8b", "armv8l"},
        "ppc64le": {"powerpc", "ppc", "ppc64", "ppcle"},
        "s390x": {"s390"},
    }

    for oci_arch, uname_arches in arch_translation_map.items():
        if platform_arch in uname_arches:
            return oci_arch
    LOGGER.warning(
        "Unknown architecture '%s'. Using 'unknown' as fallback.", platform_arch
    )
    return platform_arch


async def load_sbom_from_json(file_path: Path) -> dict[str, Any]:
    """
    A JSON loading utility that prints invalid file contents in
    case of a failure. Propagates exceptions!
    Args:
        file_path: Path to the JSON SBOM file (SPDX 2.X or CycloneDX 1.5+)
    Returns:
        The SBOM dictionary from the file.
    """
    with open(file_path, encoding="utf-8") as in_stream:
        try:
            contents = in_stream.read()
            return json.loads(contents)  # type: ignore[no-any-return]
        except JSONDecodeError:
            LOGGER.critical(
                "Expected a JSON SBOM. Found different file contents! "
                "Logging first 200 chars of the file."
            )
            LOGGER.critical(contents[:200])
            raise
