"""
Module containing classes and functions used in the release phase of SBOM
enrichment.
"""

from dataclasses import dataclass
import re
import asyncio
from pathlib import Path

import pydantic as pdc

from mobster.image import Image


@dataclass
class Component:
    """
    Internal representation of a Component for SBOM generation purposes.
    """

    name: str
    image: Image
    tags: list[str]


@dataclass
class Snapshot:
    """
    Internal representation of a Snapshot for SBOM generation purposes.
    """

    components: list[Component]


async def make_snapshot(snapshot_spec: Path) -> Snapshot:
    """
    Parse a snapshot spec from a JSON file and create an object representation
    of it. Multiarch images are handled by fetching their index image manifests
    and parsing their children as well.

    Args:
        snapshot_spec (Path): Path to a snapshot spec JSON file
    """
    with open(snapshot_spec, mode="r", encoding="utf-8") as snapshot_file:
        snapshot_model = SnapshotModel.model_validate_json(snapshot_file.read())

    component_tasks = []
    for component_model in snapshot_model.components:
        name = component_model.name
        repository = component_model.rh_registry_repo
        image_digest = component_model.image_digest
        tags = component_model.tags

        component_tasks.append(_make_component(name, repository, image_digest, tags))

    components = await asyncio.gather(*component_tasks)

    return Snapshot(components=components)


async def _make_component(
    name: str, repository: str, image_digest: str, tags: list[str]
) -> Component:
    """
    Creates a component object from input data.
    """
    image: Image = await Image.from_repository_digest(repository, image_digest)
    return Component(name=name, image=image, tags=tags)


class ComponentModel(pdc.BaseModel):
    """
    Model representing a component from the Snapshot.
    """

    name: str
    image_digest: str = pdc.Field(alias="containerImage")
    rh_registry_repo: str = pdc.Field(alias="rh-registry-repo")
    tags: list[str]

    @pdc.field_validator("image_digest", mode="after")
    @classmethod
    def is_valid_digest_reference(cls, value: str) -> str:
        """
        Validates that the digest reference is in the correct format. Does NOT
        support references with a registry port.
        """
        if not re.match(r"^[^:]+@sha256:[0-9a-f]+$", value):
            raise ValueError(f"{value} is not a valid digest reference.")

        # strip repository
        return value.split("@")[1]


class SnapshotModel(pdc.BaseModel):
    """
    Model representing a Snapshot spec file after the apply-mapping task.
    Only the parts relevant to component sboms are parsed.
    """

    components: list[ComponentModel]
