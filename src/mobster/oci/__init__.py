"""
This module contains OCI data types and code to manipulate them.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pydantic

from mobster.error import SBOMError
from mobster.utils import run_async_subprocess

if TYPE_CHECKING:
    from mobster.image import Image

logger = logging.getLogger(__name__)


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


async def get_digest_for_image_ref(image_ref: str, arch: Any = None) -> str | None:
    """
    Fetches the digest of a pullspec using oras.
    Args:
        image_ref (str): The pullspec

    Returns:
        str | None: The digest if fetched correctly. None otherwise.
    """
    with make_oci_auth_file(image_ref) as auth_file:
        cmd = [
            "oras",
            "resolve",
            "--registry-config",
            str(auth_file),
            f"{image_ref}",
        ]
        if arch:
            cmd.extend(["--platform", f"linux/{arch}"])
        code, stdout, stderr = await run_async_subprocess(cmd)
        if (not code) and stdout:
            return stdout.decode().strip()
        logger.warning(
            "Problem getting digest of a base image '%s' by oras. "
            "Got digest: '%s' and STDERR: %s",
            image_ref,
            stdout.decode(),
            stderr.decode(),
        )
        return None


async def get_objects_for_base_images(
    base_images_refs: list[str | None],
) -> dict[str, Image]:
    """
    Gets the digests for pullspecs of the base images.
    Args:
        base_images_refs (str): The pullspecs from the parsed Dockerfile

    Returns:
        dict[str, Image]: Mapping of pullspecs and their image objects
    """
    from mobster.image import Image  # noqa: F811 — deferred to avoid circular import

    image_objects = {}
    for image_ref in base_images_refs:
        if not image_ref:
            # Skips the "scratch" image
            continue
        if image_ref in image_objects:
            # Already resolved ref
            continue
        digest = await get_digest_for_image_ref(image_ref)
        if digest:
            image_objects[image_ref] = Image.from_image_index_url_and_digest(
                image_ref, digest
            )
    return image_objects


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
