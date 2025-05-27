"""A module for generating SBOM documents for products."""

import logging
from typing import Any
import uuid
from datetime import datetime, timezone
import argparse
from typing import List, Union
from pathlib import Path
import asyncio


import pydantic as pdc

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.writer.write_anything import write_file

from mobster.cmd.generate.base import GenerateCommand
from mobster.release import Snapshot, make_snapshot
from mobster.sbom import spdx


LOGGER = logging.getLogger(__name__)


class ReleaseNotes(pdc.BaseModel):
    """
    Pydantic model representing the merged data file with flattened release notes.
    """

    product_name: str = pdc.Field(alias="product_name")
    product_version: str = pdc.Field(alias="product_version")
    cpe: Union[str, List[str]] = pdc.Field(alias="cpe", union_mode="left_to_right")


class ReleaseData(pdc.BaseModel):
    release_notes: ReleaseNotes = pdc.Field(alias="releaseNotes")


class GenerateProductCommand(GenerateCommand):
    """
    Command to generate an SBOM document for a product level.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.document: Document | None = None
        self.release_notes: ReleaseNotes | None = None

    async def execute(self) -> Any:
        """
        Generate an SBOM document for a product.
        """
        LOGGER.info("Starting product SBOM generation.")
        snapshot = await make_snapshot(self.cli_args.snapshot)

        self.release_notes = parse_release_notes(self.cli_args.data)
        self.document = await create_sbom(self.release_notes, snapshot)
        LOGGER.info("Successfully created product-level SBOM.")

    async def save(self) -> None:
        assert self.release_notes, "release_notes not set"
        assert self.document, "document not set"

        fname = get_filename(self.release_notes)
        output_path: Path = self.cli_args.output.joinpath(fname)
        LOGGER.info("Saving SBOM to %s.", output_path)
        write_file(document=self.document, file_name=str(output_path), validate=True)
        print(output_path.absolute())


def create_sbom(release_notes: ReleaseNotes, snapshot: Snapshot) -> Document:
    """
    Create an SPDX document based on release notes and a snapshot.
    """
    doc_elem_id = "SPDXRef-DOCUMENT"
    product_elem_id = "SPDXRef-product"

    creation_info = spdx.get_creation_info(
        f"{release_notes.product_name} {release_notes.product_version}"
    )

    product_package = create_product_package(product_elem_id, release_notes)
    product_relationship = create_product_relationship(doc_elem_id, product_elem_id)

    component_packages = get_component_packages(snapshot.components)
    component_relationships = get_component_relationships(
        product_elem_id, component_packages
    )

    return Document(
        creation_info=creation_info,
        packages=[product_package, *component_packages],
        relationships=[product_relationship, *component_relationships],
    )


def create_product_package(
    product_elem_id: str, release_notes: ReleaseNotes
) -> Package:
    """Create SPDX package corresponding to the product."""
    if isinstance(release_notes.cpe, str):
        cpes = [release_notes.cpe]
    else:
        cpes = release_notes.cpe

    refs = [
        ExternalPackageRef(
            category=ExternalPackageRefCategory.SECURITY,
            reference_type="cpe22Type",
            locator=cpe,
        )
        for cpe in cpes
    ]

    return Package(
        spdx_id=product_elem_id,
        name=release_notes.product_name,
        version=release_notes.product_version,
        download_location=SpdxNoAssertion(),
        supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
        license_declared=SpdxNoAssertion(),
        files_analyzed=False,
        external_references=refs,
    )


def create_product_relationship(doc_elem_id: str, product_elem_id: str) -> Relationship:
    """Create SPDX relationship corresponding to the product SPDX package."""
    return Relationship(
        spdx_element_id=doc_elem_id,
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id=product_elem_id,
    )


def get_component_packages(components: List[Component]) -> List[Package]:
    """
    Get a list of SPDX packages - one per each component.

    Each component can have multiple external references - purls.
    """
    packages = []
    for component in components:
        checksum = component.image.digest.split(":", 1)[1]

        purls = [
            construct_purl(
                component.release_repository, component.image.digest, tag=tag
            )
            for tag in component.tags
        ]

        packages.append(
            Package(
                spdx_id=f"SPDXRef-component-{component.name}",
                name=component.name,
                license_declared=SpdxNoAssertion(),
                download_location=SpdxNoAssertion(),
                files_analyzed=False,
                supplier=Actor(ActorType.ORGANIZATION, "Red Hat"),
                external_references=[
                    ExternalPackageRef(
                        category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                        reference_type="purl",
                        locator=purl,
                    )
                    for purl in purls
                ],
                checksums=[
                    Checksum(algorithm=ChecksumAlgorithm.SHA256, value=checksum)
                ],
            )
        )

    return packages


def get_component_relationships(
    product_elem_id: str, packages: List[Package]
) -> List[Relationship]:
    """Get SPDX relationship for each SPDX component package."""
    return [
        Relationship(
            spdx_element_id=package.spdx_id,
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id=product_elem_id,
        )
        for package in packages
    ]


def parse_release_notes(data: Path) -> ReleaseNotes:
    """
    Parse the data file at the specified path into a ReleaseNotes object.
    """
    with open(data, "r") as fp:
        raw_json = fp.read()
        return ReleaseData.model_validate_json(raw_json).release_notes


def get_filename(release_notes: ReleaseNotes) -> str:
    """
    Get the filename for the SBOM based on release notes.
    """
    normalized_name = "-".join(release_notes.product_name.split())
    return f"{normalized_name}-{release_notes.product_version}.json"
