"""
Module containing classes and functions used in the release phase of SBOM
enrichment.
"""

import asyncio
import uuid
from dataclasses import dataclass
from pathlib import Path

import pydantic as pdc

from mobster.image import Image, parse_image_reference


class ReleaseId:
    """
    Representation of a release ID provided by Tekton.
    """

    def __init__(self, raw_id: str) -> None:
        self.id = uuid.UUID(raw_id)

    @staticmethod
    def new() -> "ReleaseId":
        """
        Generate a new random ReleaseId.
        """
        return ReleaseId(uuid.uuid4().hex)

    def __str__(self) -> str:
        return str(self.id)


@dataclass
class Component:
    """
    Representation of a Konflux Component that is being released.

    Attributes:
        name (str): Name of the component.
        image (str): The component image being released.
        tags (list[str]): List of tags under which the image is being released.
        repository (str): The OCI repository the image is being released to.
            Note that this may be different from image.repository, because that
            points to the "hidden" repository (e.g. quay.io/redhat-prod/ubi9)
            and this is the "public" repository (e.g. registry.redhat.io/ubi9).
    """

    name: str
    image: Image
    tags: list[str]
    repository: str


@dataclass
class Snapshot:
    """
    Representation of a Konflux Snapshot that is being released.

    Attributes:
        components (list[Component]): List of components being released.
    """

    components: list[Component]


async def make_snapshot(
    snapshot_spec: Path,
    digest: str | None = None,
    semaphore: asyncio.Semaphore | None = None,
) -> Snapshot:
    """
    Parse a snapshot spec from a JSON file and create an object representation
    of it. Multiarch images are handled by fetching their index image manifests
    and parsing their children as well.

    If a digest is provided, only parse the parts of the snapshot relevant to
    that image. This is used to speed up the parsing process if only a single
    image is being augmented.

    Args:
        snapshot_spec (Path): Path to a snapshot spec JSON file
        digest (str | None): Digest of the image to parse the snapshot for
        semaphore: asyncio semaphore limiting the maximum number of concurrent
            manifest fetches. If no semaphore is provided, creates an internal one
            that defaults to 8 concurrent fetches.
    """
    with open(snapshot_spec, encoding="utf-8") as snapshot_file:
        snapshot_model = SnapshotModel.model_validate_json(snapshot_file.read())

    def is_relevant(comp: "ComponentModel") -> bool:
        if digest is not None:
            return digest in comp.image_reference

        return True

    if semaphore is None:
        semaphore = asyncio.Semaphore(8)

    component_tasks = []
    for component_model in filter(is_relevant, snapshot_model.components):
        name = component_model.name
        release_repository = component_model.rh_registry_repo
        img_repository, img_digest = parse_image_reference(
            component_model.image_reference
        )
        tags = component_model.tags

        component_tasks.append(
            _make_component(
                name, img_repository, img_digest, tags, release_repository, semaphore
            )
        )

    components = await asyncio.gather(*component_tasks)
    return Snapshot(components=components)


async def _make_component(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    name: str,
    repository: str,
    image_digest: str,
    tags: list[str],
    release_repository: str,
    semaphore: asyncio.Semaphore,
) -> Component:
    """
    Creates a component object from input data.

    Args:
        name (str): name of the component
        repository (str): repository of the component's image
        image_digest (str): digest of the component image
        release_repository (str): repository the component is being
            released to (such as registry.redhat.io)
    """
    async with semaphore:
        image: Image = await Image.from_repository_digest_manifest(
            repository, image_digest
        )
    return Component(name=name, image=image, repository=release_repository, tags=tags)


class ComponentModel(pdc.BaseModel):
    """
    Pydantic model representing a component from the Snapshot.
    """

    name: str
    image_reference: str = pdc.Field(alias="containerImage")
    rh_registry_repo: str = pdc.Field(alias="rh-registry-repo")
    tags: list[str]

    @pdc.field_validator("image_reference", mode="after")
    @classmethod
    def is_valid_digest_reference(cls, value: str) -> str:
        """
        Validates that the digest reference is in the correct format and
        removes the repository part from the reference.
        """
        parse_image_reference(value)
        return value


class SnapshotModel(pdc.BaseModel):
    """
    Model representing a Snapshot spec file after the apply-mapping task.
    Only the parts relevant to component sboms are parsed.
    """

    components: list[ComponentModel]
