"""
This module contains OCI data types and code to manipulate them.
"""

import asyncio
import json
import logging
import os
import platform
import re
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pydantic

from mobster.error import SBOMError

logger = logging.getLogger(__name__)


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


async def get_image_manifest(reference: str) -> dict[str, Any]:
    """
    Gets a dictionary containing the data from a manifest for an image in a
    repository.

    Args:
        reference: Full image reference (repository@sha256<sha>).

    Returns:
        dict[str, Any]: Dictionary containing the manifest data.
    """
    logger.info("Fetching manifest for %s", reference)

    with make_oci_auth_file(reference) as authfile:
        code, stdout, stderr = await run_async_subprocess(
            [
                "oras",
                "manifest",
                "fetch",
                "--registry-config",
                str(authfile),
                reference,
            ],
            retry_times=3,
        )
    if code != 0:
        raise SBOMError(f"Could not get manifest of {reference}: {stderr.decode()}")

    return json.loads(stdout)  # type: ignore


class AuthDetails(pydantic.BaseModel):
    """Represents the authentication details for a registry."""

    token: str = pydantic.Field(alias="auth", serialization_alias="auth")


class DockerConfig(pydantic.BaseModel):
    """Represents the top-level Docker configuration with authentication information."""

    auths: dict[str, AuthDetails]


@contextmanager
def make_oci_auth_file(
    reference: str, auth: Path | None = None
) -> Generator[Path, Any, None]:
    """
    Gets path to a temporary file containing the docker config JSON for
    reference.

    Deletes the file after the with statement. If no path to the docker config
    is provided, tries using ~/.docker/config.json.
    is provided, tries using ~/.docker/config.json.

    Args:
        reference: Reference to an image in the form
            registry[:port]/repo[:tag]@sha256-X.
        auth: Existing docker config.json path.

    Yields:
        Path: Path to temporary authentication file.

    Example:
        >>> with make_oci_auth_file(ref) as auth_path:
                perform_work_in_oci()
    """
    if auth is None:
        auth = _find_auth_file()
        if auth is None:
            raise ValueError("Could not find a valid OCI authentication file.")

    if not auth.is_file():
        raise ValueError(f"No auth config file at {auth}.")

    with open(auth, encoding="utf-8") as f:
        config = DockerConfig.model_validate_json(f.read())

    tempdir = tempfile.TemporaryDirectory()
    try:
        # the file has to be named "config.json" for cosign compatibility
        new_config_path = Path(tempdir.name).joinpath("config.json")

        with open(new_config_path, "w", encoding="utf-8") as new_config_fp:
            subconfig = _get_auth_subconfig(config, reference)
            new_config_fp.write(subconfig.model_dump_json(by_alias=True))

        yield new_config_path
    finally:
        tempdir.cleanup()


def _get_auth_subconfig(config: DockerConfig, reference: str) -> DockerConfig:
    """
    Create a docker config containing token authentication only for a specific
    image reference.

    Tries to match specific repository paths first.

    Args:
        config: The docker configuration containing authentication details.
        reference: The image reference to match authentication for.

    Returns:
        DockerConfig: Docker configuration with authentication for the specific
            reference.

    Example:
        >>> config = DockerConfig(
                auths={
                    "registry.redhat.io:5000/": AuthDetails(token="another-token")
                    "registry.redhat.io:5000/specific-repo": AuthDetails(token="token"),
                },
            )
        >>> _get_auth_subconfig(
                config, "registry.redhat.io:5000/specific-repo@sha256:deadbeef"
            )
        DockerConfig(
            auths={
                "registry.redhat.io:5000/specific-repo": AuthDetails(token="token"),
            }
        )
    """
    # Remove digest from the pullspec if present
    repository = reference.split("@", 1)[0]
    # Remove tag from the pullspec if present (don't confuse port and a tag)
    repository = re.sub(r"^(.+):[^/]+$", r"\g<1>", repository)
    # registry is up to the first slash
    registry = repository.split("/", 1)[0]

    current_ref = repository

    while True:
        token = config.auths.get(current_ref)
        if token is not None:
            return DockerConfig(auths={registry: token})

        if "/" not in current_ref:
            break
        current_ref = current_ref.rsplit("/", 1)[0]

    return DockerConfig(auths={})


def _find_auth_file() -> Path | None:
    """Find an authentication file that can be used to access an OCI registry.

    Mimics the process that podman uses on login:
    https://docs.podman.io/en/v5.1.0/markdown/podman-login.1.html

    Returns:
        Path | None: A path to the authentication file if it exists, or None.
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

    for curr_auth in possible_auths:
        if curr_auth.is_file():
            return curr_auth

    return None
