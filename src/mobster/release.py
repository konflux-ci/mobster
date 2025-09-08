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
class ReleaseRepository:
    """
    A repository that a component is being released to.

    Attributes:
        repo_url: The URL of the repository (image name included)
        tags: The tags used for the release of this image.
    """

    repo_url: str
    tags: list[str]

    @property
    def repo_name(self) -> str:
        """Get the name of an OCI repository from full repository.

        Returns:
            The repository name.

        Example:
            >>> ReleaseRepository(
            >>>     "registry.redhat.io/org/suborg/rhel",
            >>>     ["latest"]
            >>> ).repo_name
            "rhel"
        """
        return self.repo_url.split("/")[-1]


@dataclass
class Component:
    """
    Representation of a Konflux Component that is being released.

    Attributes:
        name: Name of the component.
        image: The component image being released.
        release_repositories: The OCI repositories the image is being released to.
            Note that this may be different from image.repository, because that
            points to the "hidden" repository (e.g. quay.io/redhat-prod/ubi9)
            and this is the "public" repository (e.g. registry.redhat.io/ubi9).
    """

    name: str
    image: Image
    release_repositories: list[ReleaseRepository]


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
        component_tasks.append(component_model.to_component(semaphore))

    components = await asyncio.gather(*component_tasks)
    return Snapshot(components=components)


class ComponentRepositoryModel(pdc.BaseModel):
    """
    Pydantic model representing one of the repository objects in a component
    of a Snapshot.
    """

    rh_registry_repo: str = pdc.Field(alias="rh-registry-repo")
    tags: list[str]

    def to_repository(self) -> ReleaseRepository:
        """
        Dump this ComponentRepositoryModel (Snapshot representation)
        to Repository (Mobster's representation).
        Returns:
            Mobster's inner representation of this Konflux Component's
            release repository.
        """
        return ReleaseRepository(repo_url=self.rh_registry_repo, tags=self.tags)


class ComponentModel(pdc.BaseModel):
    """
    Pydantic model representing a component from the Snapshot.
    """

    name: str
    image_reference: str = pdc.Field(alias="containerImage")
    rh_registry_repo: str | None = pdc.Field(alias="rh-registry-repo", default=None)
    tags: list[str] | None = pdc.Field(default=None)
    repositories: list[ComponentRepositoryModel] = pdc.Field(default_factory=list)

    @pdc.field_validator("image_reference", mode="after")
    @classmethod
    def is_valid_digest_reference(cls, value: str) -> str:
        """
        Validates that the digest reference is in the correct format and
        removes the repository part from the reference.
        """
        parse_image_reference(value)
        return value

    async def to_component(self, semaphore: asyncio.Semaphore) -> Component:
        """
        Dump this ComponentModel (Snapshot representation) to Component
        (Mobster's representation).
        Args:
            semaphore: The semaphore which throttles the concurrency of this process.

        Returns:
            The Mobster's inner representation of the Konflux Component.
        """
        all_release_repos: list[ReleaseRepository] = [
            model.to_repository() for model in self.repositories
        ]
        # First we try to search within the new schema (.repositories).
        # If that fails, we fall back to the previous schema. According to
        # Konflux release team, the data is replicated between the legacy
        # and the new part of the schema, so we have to make sure not to
        # duplicate the data on reading it.
        if not all_release_repos and self.rh_registry_repo and self.tags:
            all_release_repos.append(
                ReleaseRepository(repo_url=self.rh_registry_repo, tags=self.tags)
            )

        img_repository, img_digest = parse_image_reference(self.image_reference)
        async with semaphore:
            image: Image = await Image.from_repository_digest_manifest(
                img_repository, img_digest
            )
        return Component(
            name=self.name, image=image, release_repositories=all_release_repos
        )


class SnapshotModel(pdc.BaseModel):
    """
    Model representing a Snapshot spec file after the apply-mapping task.
    Only the parts relevant to component sboms are parsed.
    """

    components: list[ComponentModel]
