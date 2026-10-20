"""Package with static definitions related to oci-image."""

from dataclasses import dataclass
from enum import Enum

from spdx_tools.spdx.model.relationship import RelationshipType

from mobster.cmd.generate.oci_image.spdx_utils import (
    AnnotationAdditionalImage,
    AnnotationAncestorImage,
    AnnotationBaseImage,
    AnnotationBuilderImage,
    AnnotationImage,
    AnnotationIntermediateImage,
)

HERMETO_ANNOTATION_COMMENTS = [
    '{"name": "cachi2:found_by", "value": "cachi2"}',
    '{"name": "hermeto:found_by", "value": "hermeto"}',
]


class PackageProducer(Enum):
    """
    Indicates which tool generated the package.
    """

    HERMETO = "hermeto"
    SYFT = "syft"


@dataclass(frozen=True)
class PackageInfo:
    """
    Information about a package used for matching.
    """

    spdx_id: str
    producer: PackageProducer


class MatchBy(Enum):
    """
    Information which identifier was used for match.
    """

    CHECKSUM = "checksum"
    PACKAGE_VERIFICATION_CODE = "package_verification_code"
    PURL = "purl"


@dataclass(frozen=True)
class PackageMatchInfo:
    """
    Information about package match between parent and component.
    """

    matched: bool
    parent_info: PackageInfo
    component_info: PackageInfo
    match_by: MatchBy
    identifier_value: str | None = None


class RelationshipEnd(str, Enum):
    """
    Which endpoint of a relationship holds the SPDX ID of the collected item.
    """

    SUBJECT = "spdx_element_id"
    TARGET = "related_spdx_element_id"


@dataclass(frozen=True)
class ContentKind:
    """
    Declarative description of one kind of content searched in an SBOM.

    A kind is identified by a human-readable name, relationship type,
    relationship endpoint that points to the item of interest, and the
    annotation type that item must carry. Plain content packages have no
    annotation type.

    `allows_multiple_relationships_per_endpoint` defines whether the selected
    endpoint may participate in multiple distinct relationships of the selected
    type. When set to `False`, collectors reject those one-to-many or many-to-one
    relationships per collected SBOM document.
    """

    name: str
    relationship_type: RelationshipType
    relationship_end: RelationshipEnd
    annotation_type: type[AnnotationImage] | None
    allows_multiple_relationships_per_endpoint: bool = False


# Example in parent SBOM:
# `parent DESCENDANT_OF grandparent` (grandparent is annotated is_base_image in
# the downloaded parent SBOM - it is the parent's parent)
#
# allows_multiple_relationships_per_endpoint: This content kind occurs at most
# once because the ancestor chain is linear.
BASE_IMAGE = ContentKind(
    "base image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.TARGET,
    AnnotationBaseImage,
    allows_multiple_relationships_per_endpoint=False,
)

# Example in parent SBOM:
# `grandparent DESCENDANT_OF grandgrandparent` (deeper ancestor present if the
# parent is contextualized)
#
# allows_multiple_relationships_per_endpoint: This content kind occurs at most
# once because the ancestor chain is linear.
ANCESTOR_IMAGE = ContentKind(
    "ancestor image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.TARGET,
    AnnotationAncestorImage,
    allows_multiple_relationships_per_endpoint=False,
)

# Example in parent SBOM:
# `legacy grandparent BUILD_TOOL_OF parent` (grandparent from pre-mobster era,
# annotated also as is_base_image)
#
# allows_multiple_relationships_per_endpoint: This content kind occurs at most
# once because the ancestor chain is linear.
LEGACY_BASE_IMAGE = ContentKind(
    "legacy base image",
    RelationshipType.BUILD_TOOL_OF,
    RelationshipEnd.SUBJECT,
    AnnotationBaseImage,
    allows_multiple_relationships_per_endpoint=False,
)

# SPDX IDs of image packages are generated deterministically by Mobster.
# Within one component, repeated uses of the same builder base image are
# deduplicated to a single builder image package and a single BUILD_TOOL_OF
# relationship. Builder contextualization similarly reuses the package and
# DESCENDANT_OF relationship for a repeatedly present intermediate image.
#
# Problem: Reusing an identical builder, additional, or intermediate image
# across different images in the image chain can make the concrete image/stage
# associated with its content ambiguous.
# - When a builder or additional image is reused by different images, its
#   content remains traceable to the source image, but the SBOM cannot identify
#   the concrete image into which each package was copied.
# - An identical intermediate image reused by different images cannot be
#   associated with the concrete image into which its content was copied,
#   making the concrete origin of its content ambiguous.
#
# Temporary workaround: single builder or additional image package may retain
# distinct BUILD_TOOL_OF relationships to different images in the image
# chain.
#
# In contrast, reuse of an identical intermediate image package inherited from
# the parent SBOM is rejected by
# `builder.DocumentIndexOCI.ensure_intermediate_image_package`, and the workflow
# falls back to a non-contextual SBOM.
#
# TO DO: Repeated builder, additional, and intermediate image occurrences
# across the component and ancestor chain require distinct image-package
# identities that preserve their source-image or derived-stage identity.
# Content-package CONTAINS relationships associated with the new image packages
# must be correctly updated, and correct annotations must be attributed to the
# appropriate image package.
# After that:
#  - allows_multiple_relationships_per_endpoint can be removed
#  - _validate_relationship_cardinality_for_content_kind can enforce one
#    relationship per selected endpoint for every image ContentKind
#  - the temporary safeguard in
#    builder.DocumentIndexOCI.ensure_intermediate_image_package can be removed,
#    because intermediate image identities will be unique
#
# Example in parent SBOM:
# `builder BUILD_TOOL_OF parent` (also includes builders of ancestors)
BUILDER_IMAGE = ContentKind(
    "builder image",
    RelationshipType.BUILD_TOOL_OF,
    RelationshipEnd.SUBJECT,
    AnnotationBuilderImage,
    allows_multiple_relationships_per_endpoint=True,
)

# Example in parent SBOM:
# `additional image BUILD_TOOL_OF parent` (additional image used by COPY --from)
ADDITIONAL_IMAGE = ContentKind(
    "additional image",
    RelationshipType.BUILD_TOOL_OF,
    RelationshipEnd.SUBJECT,
    AnnotationAdditionalImage,
    allows_multiple_relationships_per_endpoint=True,
)

# Example in parent SBOM:
# `intermediate DESCENDANT_OF builder` (also includes intermediates of
# ancestors)
INTERMEDIATE_IMAGE = ContentKind(
    "intermediate image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.SUBJECT,
    AnnotationIntermediateImage,
    allows_multiple_relationships_per_endpoint=False,
)
# component CONTAINS package (plain content package, no annotation type)
# allows_multiple_relationships_per_endpoint:
# A content package may have only one image/root CONTAINS owner in a document.
CONTENT_PACKAGE = ContentKind(
    "content package",
    RelationshipType.CONTAINS,
    RelationshipEnd.TARGET,
    None,
    allows_multiple_relationships_per_endpoint=False,
)


# builder-specific constants


class OriginType(str, Enum):
    """
    Type of the origin of an SBOM package.

    Type is builder when the package was copied from a builder stage or an
    external image. E.g. COPY --from=builder-stage or COPY --from=quay.io/image:latest
    Example containerfile:
        FROM image AS alias
        ...
        COPY --from=alias /content /target
        or
        COPY --from=image /content /target

    Type is intermediate when the package is sourced from an
    intermediate stage.
    Example containerfile:
        FROM builder_image AS alias
        RUN install package
        FROM parent_image
        COPY --from=alias /usr/bin/package /usr/bin/package
    """

    BUILDER = "builder"
    INTERMEDIATE = "intermediate"
    EXTERNAL = "external"
