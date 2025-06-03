"""
This module contains OCI data types and code to manipulate them.
"""

import asyncio
import json
import logging
import os
import platform
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from mobster.error import SBOMError

logger = logging.getLogger(__name__)


async def run_async_subprocess(
    cmd: list[str], env: dict[str, str] | None = None, retry_times: int = 0
) -> tuple[int, bytes, bytes]:
    """
    Run command in subprocess asynchronously.

    Args:
        cmd (list[str]): command to run in subprocess.
        env (dict[str, str] | None): environ dict
        retry_times (int): number of retries if the process ends with
            non-zero return code
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


async def get_image_manifest(reference: str) -> dict[str, Any]:
    """
    Gets a dictionary containing the data from a manifest for an image in a
    repository.

    Args:
        reference (str): full image reference (repository@sha256<sha>)
    """
    logger.info("Fetching manifest for %s", reference)

    with make_oci_auth_file(reference) as authfile:
        code, stdout, stderr = await run_async_subprocess(
            [
                "oras",
                "manifest",
                "fetch",
                "--registry-config",
                authfile,
                reference,
            ],
            retry_times=3,
        )
    if code != 0:
        raise SBOMError(f"Could not get manifest of {reference}: {stderr.decode()}")

    return json.loads(stdout)  # type: ignore


@contextmanager
def make_oci_auth_file(
    reference: str, auth: Path | None = None
) -> Generator[str, Any, None]:
    """
    Gets path to a temporary file containing the docker config JSON for
    <reference>.  Deletes the file after the with statement. If no path to the
    docker config is provided, tries using ~/.docker/config.json . Ports in the
    registry are NOT supported.

    Args:
        reference (str): Reference to an image in the form registry/repo@sha256-deadbeef
        auth (Path | None): Existing docker config.json

    Example:
        >>> with make_oci_auth_file(ref) as auth_path:
                perform_work_in_oci()
    """
    if auth is None:
        logger.debug("No auth path provided to make_oci_auth_file.")
        auth = find_auth_file()
        if auth is None:
            raise ValueError("Could not find a valid OCI authentication file.")

    if not auth.is_file():
        raise ValueError(f"No auth config file at {auth}.")

    if reference.count(":") > 1:
        raise ValueError(
            f"Multiple ':' symbols in {reference}. Registry ports are not supported."
        )

    logger.debug("Looking for auth entry for %s in auth file %s", reference, auth)

    repository, _ = reference.split("@", 1)
    # Registry is up to the first slash
    registry = repository.split("/", 1)[0]

    with open(auth, encoding="utf-8") as f:
        config = json.load(f)
    auths = config.get("auths", {})

    current_ref = repository

    tmpfile = None
    try:
        tmpfile = tempfile.NamedTemporaryFile(mode="w", delete=False)
        while True:
            token = auths.get(current_ref)
            if token is not None:
                json.dump({"auths": {registry: token}}, tmpfile)
                tmpfile.close()
                yield tmpfile.name
                return

            if "/" not in current_ref:
                break
            current_ref = current_ref.rsplit("/", 1)[0]

        json.dump({"auths": {}}, tmpfile)
        tmpfile.close()
        yield tmpfile.name
    finally:
        if tmpfile is not None:
            # this also deletes the file
            tmpfile.close()


def find_auth_file() -> Path | None:
    """
    Find an authentication file that can be used to access an OCI registry.
    Mimics the process that podman uses on login:
    https://docs.podman.io/en/v5.1.0/markdown/podman-login.1.html

    Returns:
        Path | None: A path to the authentication file if it exists, or None
    """
    if "REGISTRY_AUTH_FILE" in os.environ:
        path = Path(os.environ["REGISTRY_AUTH_FILE"])
        return path if path.is_file() else None

    possible_auths: list[Path] = []
    if platform.system() == "Linux" and "XDG_RUNTIME_DIR" in os.environ:
        possible_auths.append(
            Path(f"{os.environ.get('XDG_RUNTIME_DIR')}/containers/auth.json")
        )
    else:
        possible_auths.append(
            Path(os.path.expanduser("~/.config/containers/auth.json"))
        )

    docker_auth = Path(os.path.expanduser("~/.docker/config.json"))
    possible_auths.append(docker_auth)
    logger.debug("List of possible OCI auth files: %s", possible_auths)

    for curr_auth in possible_auths:
        if curr_auth.is_file():
            return curr_auth

    return None
