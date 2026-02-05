"""
Functions and types for builder content contextualization.
"""

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Literal

import pydantic as pdc
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType

from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    validate_and_compare_purls,
)
from mobster.cmd.generate.oci_image.spdx_utils import DocumentIndexOCI, PackageContext
from mobster.sbom.spdx import get_package_purl

LOGGER = logging.getLogger(__name__)


class BuilderContextualizationError(Exception):
    """
    Raised when an unexpected error occurred while contextualizing builder
    content.
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
    """
    Pydantic model representing origin information about a package from Capo.

    Attributes:
        purl: string representation of a PackageURL for the scanned package
        checksums: list of checksums for the package in string representation
        dependency_of_purl: PURL of the package that this package is a DEPENDENCY_OF
        origin_type: "builder" or "intermediate" based on the origin of the package
        pullspec: pullspec of the image this package originates from
    """

    purl: str
    checksums: list[str] = pdc.Field(default_factory=list)
    dependency_of_purl: str | None = pdc.Field(default=None)
    origin_type: Literal["builder"] | Literal["intermediate"]
    pullspec: str


class BuilderPkgMetadata(pdc.BaseModel):
    """
    Pydantic model representing origin information of all packages from Capo.

    Attributes:
        packages: list of package origin models from a build
    """

    packages: list[BuilderPkgMetadataItem]


class OriginType(Enum):
    """
    Type of an origin of an SBOM package.

    Type is builder when the package was copied from a builder stage or an
    external image.

    Type is intermediate when the package was created during a build in an
    intermediate stage.
    """

    BUILDER = auto()
    INTERMEDIATE = auto()


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

    Args:
        index: indexed SPDX document to source packages from
        builder_metadata: parsed builder package metadata from Capo

    Returns:
        An associative list mapping SPDX IDs of the packages in the passed
        index to their true image origins.
    """
    origins = []

    for pkg_meta in builder_metadata.packages:
        packages_by_purl = index.packages_by_purl(pkg_meta.purl)
        if len(packages_by_purl) == 0:
            continue

        pkg_to_contextualize = None
        if len(packages_by_purl) == 1:
            pkg_to_contextualize = packages_by_purl[0]
        else:
            if pkg_meta.dependency_of_purl is None:
                # can't resolve ambiguous PURL, this package should not be
                # contextualized
                continue

            pkg_to_contextualize = _resolve_dependency_of(
                packages_by_purl,
                index,
                pkg_meta.dependency_of_purl,
            )
            if pkg_to_contextualize is None:
                # can't resolve ambiguous PURL, this package should not be
                # contextualized
                continue

        origin_type = (
            OriginType.BUILDER
            if pkg_meta.origin_type == "builder"
            else OriginType.INTERMEDIATE
        )

        origins.append(
            (
                pkg_to_contextualize.pkg.spdx_id,
                Origin(pullspec=pkg_meta.pullspec, type=origin_type),
            )
        )

    return origins


def _resolve_dependency_of(
    packages: list[PackageContext],
    index: DocumentIndexOCI,
    dependency_of_purl: str,
) -> PackageContext | None:
    """
    Try to find the package in the document index that matches the
    BuilderPkgMetadataItem object using dependency_of_purl and relationships in
    the document index.

    Args:
        packages: List of package contexts to search through
        index: Document index containing SPDX packages and relationships
        dependency_of_purl: PURL string of the package that the target package
            is a dependency of

    Returns:
        PackageContext matching the criteria, or None if package could not be
        determined.
    """
    for pkg_context in packages:
        rels = pkg_context.filter_parent_relationships(RelationshipType.DEPENDENCY_OF)
        if len(rels) == 0:
            continue

        dependency_of_spdx_id = rels[0].related_spdx_element_id
        if not isinstance(dependency_of_spdx_id, str):
            raise BuilderContextualizationError(
                "DEPENDENCY_OF relationship has empty related_spdx_element_id"
            )

        parent_pkg_context = index.try_package_by_spdx_id(dependency_of_spdx_id)
        if parent_pkg_context is None:
            raise BuilderContextualizationError(
                f"Invalid SBOM; Package with id {dependency_of_spdx_id} "
                "from relationship is not present."
            )

        parent_purl = get_package_purl(parent_pkg_context.pkg)
        if not parent_purl:
            continue

        if validate_and_compare_purls(parent_purl, dependency_of_purl):
            return pkg_context

    return None


def resolve_origins(
    index: DocumentIndexOCI, origins: list[tuple[str, Origin]]
) -> DocumentIndexOCI:
    """
    Modify the passed index to reflect the passed origins information. Adjusts
    relationships in the document so they reflect the true origins of packages.

    Args:
        index: object indexing the underlying SPDX document
        origins: associate list mapping package SPDX IDs to their origins

    Returns:
        DocumentIndexOCI: the modified index
    """

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

        if origin.type == OriginType.INTERMEDIATE:
            int_img_pkg_ctx = index.ensure_intermediate_image_package(
                matched_img_pkg_ctx
            )
            new_parent_spdx_id = int_img_pkg_ctx.pkg.spdx_id

        index.reparent_relationship(current_relationship, new_parent_spdx_id)

    return index


def _find_current_image_contains_relationship(
    index: DocumentIndexOCI, pkg_spdx_id: str
) -> Relationship | None:
    """
    Find the current relationship where an image package CONTAINS the package
    with the passed spdx_id.

    Args:
        index: Document index containing SPDX packages and relationships
        pkg_spdx_id: SPDX ID of the package to find CONTAINS relationship for

    Returns:
        Relationship where an image package CONTAINS the specified package,
        or None if no such relationship exists.
    """
    current_relationship = None

    for img_pkg_ctx in index.image_packages():
        rels = [
            rel
            for rel in img_pkg_ctx.filter_parent_relationships(
                RelationshipType.CONTAINS
            )
            if rel.related_spdx_element_id == pkg_spdx_id
        ]
        if len(rels) == 0:
            continue

        current_relationship = rels[0]

    return current_relationship
