"""Module for augmenting the oci-image SBOM with information from a parsed Dockerfile"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyclonedx.model import Property
from cyclonedx.model.component import Component
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.cmd.generate.oci_image.spdx_utils import find_spdx_root_packages_spdxid
from mobster.image import Image
from mobster.oci import make_oci_auth_file, run_async_subprocess
from mobster.sbom.cyclonedx import get_component
from mobster.sbom.spdx import get_image_package

LOGGER = logging.getLogger(__name__)


async def get_base_images_refs_from_dockerfile(
    parsed_dockerfile: dict[str, Any], target_stage: str | None = None
) -> list[str | None]:
    """
    Reads the base images from provided parsed dockerfile, does not include
    stages after the target of the build. So the last image returned is
    the parent image used.

    Args:
        parsed_dockerfile (dict[str, Any]): Contents of the parsed dockerfile
        target_stage (str): The target stage for the build
    Returns:
        list[str | None]: List of base images used during build as extracted
                          from the dockerfile in the order they were used.
                          `FROM SCRATCH` is identified as `None`.

    Example:
    If the Dockerfile looks like
    FROM registry.access.redhat.com/ubi8/ubi:latest as builder
    ...
    FROM builder
    ...

    Then the relevant part of parsed_dockerfile look like
    {
        "Stages": [
            {
                "BaseName": "registry.access.redhat.com/ubi8/ubi:latest",
                "As": "builder",
                "From": {"Image": "registry.access.redhat.com/ubi8/ubi:latest"},
            },
            {
                "BaseName": "builder",
                "From": {"Stage": {"Named": "builder", "Index": 0}},
            },
        ]
    },
    """
    base_images_pullspecs: list[str | None] = []
    for stage in parsed_dockerfile.get("Stages", []):
        is_actually_image = True

        from_field = stage.get("From", {})
        # Ignore scratch image as well as
        # references to previous stages
        if "Stage" in from_field:
            is_actually_image = False
        if from_field.get("Scratch"):
            # It is an empty image
            base_images_pullspecs.append(None)
            is_actually_image = False
        base_name: str = stage.get("BaseName")
        if is_actually_image and base_name and not base_name.startswith("oci-archive:"):
            # flatpak archives are not real base images. So we skip them
            base_images_pullspecs.append(base_name)

        # Don't include images after the target used for build
        alias = stage.get("As")
        if target_stage and alias and alias == target_stage:
            # The `AS` keyword of this stage matches the target
            break
        if target_stage and not alias and base_name == target_stage:
            # This stage does not use the `AS` keyword,
            # the pull-spec matches the target
            break
    return base_images_pullspecs


async def get_digest_for_image_ref(image_ref: str) -> str | None:
    """
    Fetches the digest of a pullspec using oras.
    Args:
        image_ref (str): The pullspec

    Returns:
        str | None: The digest if fetched correctly. None otherwise.
    """
    with make_oci_auth_file(image_ref) as auth_file:
        code, stdout, stderr = await run_async_subprocess(
            [
                "oras",
                "resolve",
                "--registry-config",
                str(auth_file),
                f"{image_ref}",
            ],
        )
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


async def get_image_objects_from_file(base_images_digests: Path) -> dict[str, Image]:
    """
    Parses the base image digest file into a dictionary of
    image references present in a Dockerfile and Image
    objects.
    Args:
        base_images_digests (Path): File containing the digests of images.
            expects the format <image_ref> <name>:<tag>@sha256:<digest>

    Returns:
        dict[str, Image]: Mapping of the references to Image objects
    """
    base_images_mapping = {}
    with open(base_images_digests, encoding="utf-8") as input_file_stream:
        for line in input_file_stream.readlines():
            if not line:
                continue
            line = line.strip()
            image_ref, image_full_reference = re.split(r"\s+", line)
            image_obj = Image.from_oci_artifact_reference(image_full_reference)
            base_images_mapping[image_ref] = image_obj
    return base_images_mapping


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


async def _get_images_and_their_annotations(
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
        assert image_obj, (
            f"Cannot get information about base image "
            f"{image_ref} mentioned in the Dockerfile!"
        )
        if index == len(base_images_refs) - 1:
            component_annotation = {
                "name": "konflux:container:is_base_image",
                "value": "true",
            }
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


async def _get_cdx_components_from_base_images(
    base_images_refs: list[str | None], base_images: dict[str, Image]
) -> list[Component]:
    """
    Transforms the list of base images and their mapping to
    an Image object into a list of CDX Components.
    Args:
        base_images_refs (list[str]):
            list of image references, the last one is the parent image.
        base_images (dict[str, Image]):
            mapping of those references to Image objects.

    Returns:
        list[cyclonedx.model.component.Component]:
            List of CDX components to be added to an SBOM.
    """
    components = []
    for image_component, annotations in await _get_images_and_their_annotations(
        base_images_refs, base_images
    ):
        component = get_component(image_component)
        for annotation in annotations:
            component.properties.add(Property(**annotation))
        components.append(component)
    return components


async def _get_spdx_packages_from_base_images(
    base_images_refs: list[str | None], base_images: dict[str, Image]
) -> tuple[list[Package], list[Annotation]]:
    """
    Transforms the list of base images and their mapping to
    an Image object into a list of SPDX Packages.
    Args:
        base_images_refs (list[str | None]):
            list of image references, the last one is the parent image.
        base_images (dict[str, Image]):
            mapping of those references to Image objects.

    Returns:
        list[spdx_tools.spdx.model.Package]:
            List of SPDX packages to be added to an SBOM.
    """
    packages = []
    result_annotations = []
    for image, annotations in await _get_images_and_their_annotations(
        base_images_refs, base_images
    ):
        package = get_image_package(image, spdx_id=image.propose_spdx_id())
        for annotation in annotations:
            result_annotations.append(
                Annotation(
                    spdx_id=package.spdx_id,
                    annotation_type=AnnotationType.OTHER,
                    annotation_date=datetime.now(timezone.utc),
                    annotator=Actor(
                        actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                    ),
                    annotation_comment=json.dumps(annotation, separators=(",", ":")),
                )
            )
        packages.append(package)
    return packages, result_annotations


async def _extend_spdx_with_base_images(
    sbom: Document, base_image_refs: list[str | None], base_images: dict[str, Image]
) -> None:
    """
    Extend the SPDX SBOM with the base images.
    Args:
        sbom (spdx_tools.spdx.model.Document):
            SBOM to be edited.
        base_image_refs (list[str | None]):
            list of image references, the last one is the parent image.
        base_images (dict[str, Image]):
            mapping of those references to Image objects.

    Returns:
        None: Nothing is returned, changes are performed in-place.
    """
    packages, annotations = await _get_spdx_packages_from_base_images(
        base_image_refs, base_images
    )
    if not packages:
        return
    sbom.packages.extend(packages)
    sbom.annotations.extend(annotations)
    root_spdxids = await find_spdx_root_packages_spdxid(sbom)
    for root_spdxid in root_spdxids:
        for package in packages[:-1]:
            # Those are builder images
            sbom.relationships.append(
                Relationship(
                    spdx_element_id=package.spdx_id,
                    relationship_type=RelationshipType.BUILD_TOOL_OF,
                    related_spdx_element_id=root_spdxid,
                )
            )
        # Handle Parent image
        sbom.relationships.append(
            Relationship(
                spdx_element_id=root_spdxid,
                relationship_type=RelationshipType.DESCENDANT_OF,
                related_spdx_element_id=packages[-1].spdx_id,
            )
        )


async def _extend_cdx_with_base_images(
    sbom_wrapper: CycloneDX1BomWrapper,
    base_image_refs: list[str | None],
    base_images: dict[str, Image],
) -> None:
    """
    Extend the CDX SBOM with the base images.
    Args:
        sbom_wrapper (CycloneDX1BomWrapper):
            SBOM to be edited.
        base_image_refs (list[str]):
            list of image references, the last one is the parent image.
        base_images (dict[str, Image]):
            mapping of those references to Image objects.

    Returns:
        None: Nothing is returned, changes are performed in-place.
    """
    components = await _get_cdx_components_from_base_images(
        base_image_refs, base_images
    )
    sbom_wrapper.formulation.append(
        {"components": CycloneDX1BomWrapper.get_component_dicts(components)}
    )


async def extend_sbom_with_base_images_from_dockerfile(
    sbom: CycloneDX1BomWrapper | Document,
    parsed_dockerfile: dict[str, Any],
    base_images_objects: dict[str, Image] | None = None,
    dockerfile_target_stage: str | None = None,
) -> None:
    """
    Extend the SBOM with the base images from the provided Dockerfile
    according to the build target stage.
    Args:
        sbom (CycloneDX1BomWrapper | spdx_tools.spdx.model.Document): SBOM to be edited.
        parsed_dockerfile (dict[str, Any]):
            The output of `dockerfile-json` command loaded into a dictionary.
        base_images_objects (dict[str, Image] | None):
            Pre-resolved map
        dockerfile_target_stage (Optional[str]):
            The build target for this build, determines which image is considered parent
            and what images were not used at all.

    Returns:
        None: Nothing is returned, changes are performed in-place.
    """
    # Loading information from Dockerfile
    base_images_refs = await get_base_images_refs_from_dockerfile(
        parsed_dockerfile, dockerfile_target_stage
    )
    base_images = base_images_objects or await get_objects_for_base_images(
        base_images_refs
    )

    if isinstance(sbom, CycloneDX1BomWrapper):
        await _extend_cdx_with_base_images(sbom, base_images_refs, base_images)
    elif isinstance(sbom, Document):
        await _extend_spdx_with_base_images(sbom, base_images_refs, base_images)
