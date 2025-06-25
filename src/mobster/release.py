"""
Module containing classes and functions used in the release phase of SBOM
enrichment.
"""

import asyncio
from dataclasses import dataclass
from pathlib import Path

import pydantic as pdc

from mobster.image import ARTIFACT_PATTERN, Image


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


async def make_snapshot(snapshot_spec: Path, digest: str | None = None) -> Snapshot:
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
    """
    with open(snapshot_spec, encoding="utf-8") as snapshot_file:
        snapshot_model = SnapshotModel.model_validate_json(snapshot_file.read())

    def is_relevant(comp: "ComponentModel") -> bool:
        if digest is not None:
            return comp.image_digest == digest

        return True

    component_tasks = []
    for component_model in filter(is_relevant, snapshot_model.components):
        name = component_model.name
        release_repository = component_model.rh_registry_repo
        repository = component_model.repository
        image_digest = component_model.image_digest
        tags = component_model.tags

        component_tasks.append(
            _make_component(name, repository, image_digest, tags, release_repository)
        )

    components = await asyncio.gather(*component_tasks)
    return Snapshot(components=components)


async def _make_component(
    name: str,
    repository: str,
    image_digest: str,
    tags: list[str],
    release_repository: str,
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
    image: Image = await Image.from_repository_digest_manifest(repository, image_digest)
    return Component(name=name, image=image, repository=release_repository, tags=tags)


class ComponentModel(pdc.BaseModel):
    """
    Pydantic model representing a component from the Snapshot.
    """

    name: str
    image_digest: str = pdc.Field(alias="containerImage")
    rh_registry_repo: str = pdc.Field(alias="rh-registry-repo")
    tags: list[str]
    repository: str

    @pdc.field_validator("image_digest", mode="after")
    @classmethod
    def is_valid_digest_reference(cls, value: str) -> str:
        """
        Validates that the digest reference is in the correct format and
        removes the repository part from the reference.
        """
        match = ARTIFACT_PATTERN.match(value)
        if not match:
            raise ValueError("Image reference does not match the RE.")

        digest = match.group("digest")
        if not digest.startswith("sha256:"):
            raise ValueError("Only sha256 digests are supported")

        return digest


class SnapshotModel(pdc.BaseModel):
    """
    Model representing a Snapshot spec file after the apply-mapping task.
    Only the parts relevant to component sboms are parsed.
    """

    components: list[ComponentModel]
