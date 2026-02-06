from dataclasses import dataclass
from enum import Enum, auto
import logging
from typing import Literal

import pydantic as pdc
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.relationship import RelationshipType, Relationship
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.json.json_writer import write_document_to_file

from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    validate_and_compare_purls,
)
from mobster.sbom.spdx import get_package_purl
from mobster.cmd.generate.oci_image.spdx_utils import DocumentIndexOCI, PackageContext

LOGGER = logging.getLogger(__name__)


class BuilderContextualizationError(Exception):
    """
    Raised when an unexpected error occurred while contextualizing builder
    content.
    """


class AmbiguousPurlError(BuilderContextualizationError):
    """
    Raised when a Package URL is found in multiple packages and could not be
    disambiguated using dependency inspection.
    """


class MissingImagePackageForPullspec(BuilderContextualizationError):
    """
    Raised when an image package could not be found based on a pullspec.
    """


class MissingImageContainsPackage(BuilderContextualizationError):
    """
    Raised when a CONTAINS relationship between an image package and a package
    is not found in the SBOM.
    """


class BuilderPkgMetadataItem(pdc.BaseModel):
    purl: str
    checksums: list[str] = pdc.Field(default_factory=list)
    dependency_of_purl: str | None = pdc.Field(default=None)
    origin_type: Literal["builder"] | Literal["intermediate"]
    pullspec: str


class BuilderPkgMetadata(pdc.BaseModel):
    packages: list[BuilderPkgMetadataItem]


class OriginType(Enum):
    """
    Type of an origin of an SBOM package.

    Type is builder when the package was copied from a builder stage or an
    external image.

    Type is intermediate when the package was created during a build in an
    intermediate stage.
    """

    Builder = auto()
    Intermediate = auto()


@dataclass
class Origin:
    """
    Dataclass representing a "true" origin of a package in an SBOM.

    Attributes:
        pullspec: pullspec of the image that a package originates from
        type: type of origin of the package (builder or intermediate)
    """

    pullspec: str
    type: OriginType


def generate_origins(
    index: DocumentIndexOCI, builder_metadata: BuilderPkgMetadata
) -> list[tuple[str, Origin]]:
    """
    Generate origins of packages in a document based on metadata.

    Arguments:
        index: indexed SPDX document to source packages from
        builder_metadata: parsed builder package metadata from Capo

    Returns:
        An associative list mapping SPDX IDs of the packages in the passed
        index to their true image origins.
    """
    origins = list()

    for pkg_meta in builder_metadata.packages:
        packages_by_purl = index.packages_by_purl(pkg_meta.purl)
        if len(packages_by_purl) == 0:
            continue

        if len(packages_by_purl) == 1:
            pkg_to_contextualize = packages_by_purl[0]
        else:
            pkg_to_contextualize = _resolve_dependency_of(
                packages_by_purl,
                index,
                pkg_meta,
            )
            if pkg_to_contextualize is None:
                raise AmbiguousPurlError(
                    f"Could not disambiguate PURL: {pkg_meta.purl}"
                )

        origin_type = (
            OriginType.Builder
            if pkg_meta.origin_type == "builder"
            else OriginType.Intermediate
        )

        origins.append(
            (
                pkg_to_contextualize.pkg.spdx_id,
                Origin(pullspec=pkg_meta.pullspec, type=origin_type),
            )
        )

    return origins


def _resolve_dependency_of(
    packages_by_purl: list[PackageContext],
    index: DocumentIndexOCI,
    pkg_meta: BuilderPkgMetadataItem,
) -> PackageContext | None:
    for pkg_context in packages_by_purl:
        rels = pkg_context.filter_parent_relationships(RelationshipType.DEPENDENCY_OF)
        if len(rels) == 0:
            continue

        dependency_of_spdx_id = rels[0].related_spdx_element_id
        parent_pkg_context = index.package_by_spdx_id(dependency_of_spdx_id)
        if parent_pkg_context is None:
            raise BuilderContextualizationError(
                f"Invalid SBOM; Package with id {dependency_of_spdx_id} "
                "from relationship is not present."
            )

        parent_purl = get_package_purl(parent_pkg_context.pkg)
        if not parent_purl:
            continue

        if validate_and_compare_purls(parent_purl, pkg_meta.dependency_of_purl):
            return pkg_context

    return None


def resolve_origins(
    index: DocumentIndexOCI, origins: list[tuple[str, Origin]]
) -> DocumentIndexOCI:
    for pkg_spdx_id, origin in origins:
        current_relationship = _find_current_image_contains_relationship(
            index,
            pkg_spdx_id,
        )
        if current_relationship is None:
            raise MissingImageContainsPackage(
                "Could not find image package CONTAINS "
                f"relationship to package {pkg_spdx_id}."
            )

        matched_img_pkg_ctx = index.image_package_by_pullspec(origin.pullspec)
        if matched_img_pkg_ctx is None:
            raise MissingImagePackageForPullspec(
                f"Could not find image package for pullspec: {origin.pullspec}"
            )
        new_parent_spdx_id = matched_img_pkg_ctx.pkg.spdx_id

        if origin.type == OriginType.Intermediate:
            int_img_pkg_ctx = index.ensure_intermediate_image_package(
                matched_img_pkg_ctx
            )
            new_parent_spdx_id = int_img_pkg_ctx.pkg.spdx_id

        index.reparent_relationship(current_relationship, new_parent_spdx_id)

    return index


def _find_current_image_contains_relationship(
    index: DocumentIndexOCI, pkg_spdx_id: str
) -> Relationship | None:
    # find the current relationship where an image package CONTAINS
    # the pkg spdx_id that needs to be updated
    current_relationship = None

    for img_pkg_ctx in index.image_packages():
        rels = [
            rel
            for rel in img_pkg_ctx.parent_relationships
            if rel.related_spdx_element_id == pkg_spdx_id
            and rel.relationship_type == RelationshipType.CONTAINS
        ]
        if len(rels) == 0:
            continue

        current_relationship = rels[0]

    return current_relationship


def main():
    document: Document = parse_file("mobster.sbom.json")

    with open("mobster.builder.json", "r") as fp:
        metadata = BuilderPkgMetadata.model_validate_json(fp.read())

    index = DocumentIndexOCI(document)

    origins = generate_origins(index, metadata)
    index = resolve_origins(index, origins)

    write_document_to_file(index.doc, "contextualized.json", validate=False)


if __name__ == "__main__":
    main()
