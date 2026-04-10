"""Format-agnostic utilities for base image handling in multi-stage builds."""

import logging
from typing import Any

from mobster.cmd.generate.oci_image.constants import IS_BASE_IMAGE_ANNOTATION
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.utils import run_async_subprocess

LOGGER = logging.getLogger(__name__)


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
        LOGGER.warning(
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


async def get_images_and_their_annotations(
    base_images_refs: list[str | None], base_images: dict[str, Image]
) -> list[tuple[Image, list[dict[str, str]]]]:
    """
    Gets Image objects and their annotation dictionaries. The last
    image is the parent image.

    Args:
        base_images_refs (list[str | None]): List of image references in the order
            from the Dockerfile. One image can be used multiple times, but
            the parent image reference is the last reference in this list.
        base_images:
            Dictionary which maps each image reference to an initialized
            Image object. This mapping is not expected to be sorted.
    Returns:
        list[tuple[Image, list[dict[str, str]]]]: List of tuples, each
        contains the corresponding Image object and the annotations
        that should be applied to it. If it was used multiple times,
        multiple annotations will be present.
    """
    tuples_of_images_and_annotations: list[tuple[Image, list[dict[str, str]]]] = []
    already_used_base_images: set[str] = set()
    last_ans_ref = None
    for index, image_ref in enumerate(base_images_refs):
        if not image_ref:
            # This is a `FROM SCRATCH` image
            continue
        image_obj = base_images.get(image_ref)
        if not image_obj:
            LOGGER.warning(
                "Cannot get information about base image "
                "%s! THIS MEANS THE PRODUCED SBOM WILL BE"
                "INCOMPLETE!",
                image_ref,
            )
            continue
        if index == len(base_images_refs) - 1:
            component_annotation = IS_BASE_IMAGE_ANNOTATION
        else:
            component_annotation = {
                "name": "konflux:container:is_builder_image:for_stage",
                "value": str(index),
            }

        # If the base image is used in multiple stages
        # then instead of adding another component
        # only additional property is added to the existing component
        digest = image_obj.digest
        if digest not in already_used_base_images:
            tuples_of_images_and_annotations.append((image_obj, []))
        # Add the annotation to the component
        # (same image can be used for multiple stages)
        already_present_component: tuple[Image, list[dict[str, str]]] = next(
            # We suppress a pylint warning because the closure is not stored anywhere
            # so rewriting its reference does not cause troubles here
            filter(
                lambda x: x[0].digest == digest,  # pylint: disable=cell-var-from-loop
                tuples_of_images_and_annotations,  # pylint: enable=cell-var-from-loop
            )
        )
        already_present_component[1].append(component_annotation)
        already_used_base_images.add(digest)
        last_ans_ref = already_present_component
    # Ensure that the parent image is the last item in the list,
    # it was last in the list `base_images_refs`, but could have
    # occurred multiple times
    if last_ans_ref:
        tuples_of_images_and_annotations.remove(last_ans_ref)
        tuples_of_images_and_annotations.append(last_ans_ref)
    return tuples_of_images_and_annotations
