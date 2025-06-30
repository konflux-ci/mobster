"""A module for generating SBOM documents for products."""

import logging
import sys
from pathlib import Path
from typing import Any

import pydantic as pdc
import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer
from packageurl import PackageURL
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.base import GenerateCommand
from mobster.release import Component, Snapshot, make_snapshot
from mobster.sbom import spdx

LOGGER = logging.getLogger(__name__)


class ReleaseNotes(pdc.BaseModel):
    """Pydantic model representing the release notes."""

    product_name: str = pdc.Field(alias="product_name")
    product_version: str = pdc.Field(alias="product_version")
    cpe: str | list[str] = pdc.Field(alias="cpe", union_mode="left_to_right")


class ReleaseData(pdc.BaseModel):
    """Pydantic model representing the merged data file."""

    release_notes: ReleaseNotes = pdc.Field(alias="releaseNotes")


class GenerateProductCommand(GenerateCommand):
    """Command to generate a product-level SBOM document."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.document: Document | None = None
        self.release_notes: ReleaseNotes | None = None

    async def execute(self) -> None:
        """Generate an SBOM document for a product."""
        LOGGER.info("Starting product SBOM generation.")
        snapshot = await make_snapshot(self.cli_args.snapshot)

        self.release_notes = parse_release_notes(self.cli_args.release_data)
        self.document = create_sbom(self.release_notes, snapshot)
        LOGGER.info("Successfully created product-level SBOM.")

    async def save(self) -> None:
        """
        Save the current generated SBOM document to a file or stdout.
        """
        assert self.release_notes, "release_notes not set"
        assert self.document, "document not set"

        if self.cli_args.output:
            output_path = self.cli_args.output
            LOGGER.info("Saving SBOM to %s.", output_path)
            await self._save_file(self.document, output_path)
        else:
            LOGGER.info("Outputting SBOM to stdout.")
            await self._save_stdout(self.document)

    async def _save_stdout(self, document: Document) -> None:
        """Validate and print the passed SPDX document to stdout.

        Args:
            document: The SPDX document to output.
        """
        return await self._save(document, sys.stdout)

    async def _save_file(self, document: Document, output: Path) -> None:
        """Validate and save the passed SPDX document to a specified path.

        Args:
            document: The SPDX document to save.
            output: The file path to save to.
        """
        with open(output, "w", encoding="utf-8") as fp:
            await self._save(document, fp)

    async def _save(self, document: Document, stream: Any) -> None:
        """Validate and save the passed SPDX document to a stream.

        Args:
            document: The SPDX document to save.
            stream: The stream to write to.
        """
        spdx_json_writer.write_document_to_stream(
            document=document, stream=stream, validate=True
        )


def create_sbom(release_notes: ReleaseNotes, snapshot: Snapshot) -> Document:
    """Create an SPDX document based on release notes and a snapshot.

    Args:
        release_notes: The release notes containing product information.
        snapshot: The snapshot containing component information.

    Returns:
        Document: The generated SPDX document.
    """
    product_elem_id = "SPDXRef-product"

    creation_info = spdx.get_creation_info(
        f"{release_notes.product_name} {release_notes.product_version}"
    )

    product_package = create_product_package(product_elem_id, release_notes)
    product_relationship = spdx.get_root_package_relationship(product_elem_id)

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
    """Create SPDX package corresponding to the product.

    Args:
        product_elem_id: The SPDX element ID for the product.
        release_notes: The release notes containing product information.

    Returns:
        Package: The SPDX package for the product.
    """
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

    return spdx.get_package(
        spdx_id=product_elem_id,
        name=release_notes.product_name,
        version=release_notes.product_version,
        external_refs=refs,
        checksums=[],
    )


def without_sha_header(digest: str) -> str:
    """Return an image digest without the 'sha256:' header.

    Args:
        digest: The image digest with sha256 header.

    Returns:
        str: The digest without the header.
    """
    return digest.split(":", 1)[1]


def get_repo_name(repository: str) -> str:
    """Get the name of an OCI repository from full repository.

    Args:
        repository: The full repository string.

    Returns:
        str: The repository name.

    Example:
        >>> get_repo_name("registry.redhat.io/org/suborg/rhel")
        "rhel"
    """
    return repository.split("/")[-1]


def get_component_packages(components: list[Component]) -> list[Package]:
    """Get a list of SPDX packages - one per each component.

    Each component can have multiple external references - purls.

    Args:
        components: List of components to convert to SPDX packages.

    Returns:
        list[Package]: List of SPDX packages.
    """
    packages = []
    for component in components:
        checksum = without_sha_header(component.image.digest)
        repo_name = get_repo_name(component.repository)

        purls = [
            PackageURL(
                type="oci",
                name=repo_name,
                version=component.image.digest,
                qualifiers={"repository_url": component.repository, "tag": tag},
            ).to_string()
            for tag in component.tags
        ]

        external_refs = [
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=purl,
            )
            for purl in purls
        ]

        checksums = [Checksum(algorithm=ChecksumAlgorithm.SHA256, value=checksum)]

        package = spdx.get_package(
            spdx_id=f"SPDXRef-component-{component.name}",
            name=component.name,
            version=None,
            external_refs=external_refs,
            checksums=checksums,
        )
        packages.append(package)

    return packages


def get_component_relationships(
    product_elem_id: str, packages: list[Package]
) -> list[Relationship]:
    """Get SPDX relationship for each SPDX component package.

    Args:
        product_elem_id: The SPDX ID of the product element.
        packages: List of SPDX packages to create relationships for.

    Returns:
        list[Relationship]: List of SPDX relationships.
    """
    return [
        Relationship(
            spdx_element_id=package.spdx_id,
            relationship_type=RelationshipType.PACKAGE_OF,
            related_spdx_element_id=product_elem_id,
        )
        for package in packages
    ]


def parse_release_notes(data: Path) -> ReleaseNotes:
    """Parse the data file at the specified path into a ReleaseNotes object.

    Args:
        data: Path to the release data file.

    Returns:
        ReleaseNotes: Parsed ReleaseNotes object.
    """
    with open(data, encoding="utf-8") as fp:
        raw_json = fp.read()
        return ReleaseData.model_validate_json(raw_json).release_notes
