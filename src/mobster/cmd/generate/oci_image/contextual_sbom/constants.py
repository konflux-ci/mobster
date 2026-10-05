"""Package with static definitions related to oci-image."""

from dataclasses import dataclass
from enum import Enum

from spdx_tools.spdx.model.relationship import RelationshipType

from mobster.cmd.generate.oci_image.spdx_utils import (
    AnnotationAncestorImage,
    AnnotationBaseImage,
    AnnotationBuilderImage,
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
    annotation_type: (
        type[AnnotationBaseImage]
        | type[AnnotationAncestorImage]
        | type[AnnotationBuilderImage]
        | type[AnnotationIntermediateImage]
        | None
    )
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

# allows_multiple_relationships_per_endpoint for BUILDER_IMAGE and
# INTERMEDIATE_IMAGE explanation:
# SPDX IDs of image packages are generated deterministically by Mobster. This
# complicates inheritance of builders and their intermediates from parent SBOM
# to component SBOM in specific edge-cases.
# There are two situations where the same builder image is used in multiple
# parts of the image chain and deterministic naming may collide*:
#
# - The same builder may build the component and one or more of its ancestors:
#   `builder* BUILD_TOOL_OF parent` and `builder* BUILD_TOOL_OF component`.
#   Parent contextualization first supplies the parent's already-existing
#   intermediate to the component. If both stages have intermediate content,
#   component builder contextualization later tries to create the same
#   deterministic intermediate identity:
#   `builder-intermediate* DESCENDANT_OF builder` (parent) and
#   `builder-intermediate* DESCENDANT_OF builder` (component)
#
# - The same builder may build two ancestors present in the parent SBOM, i.e.,
#   `builder* BUILD_TOOL_OF parent` and `builder* BUILD_TOOL_OF grandparent`.
#   Similar situation as previous - if both ancestors copy content from
#   intermediate layers, then intermediate image packages with identical names
#   are derived from these builders and those will interfere* in parent SBOM:
#   `builder-intermediate* DESCENDANT_OF builder` (parent) and
#   `builder-intermediate* DESCENDANT_OF builder` (grandparent)
#
# Current implementation:
# A reused builder image package may have distinct `BUILD_TOOL_OF`
# relationships to ancestors and/or to the component. This is allowed, with a
# tradeoff regarding content package origin tracking in the contextual SBOM.
# In case of `builder CONTAINS vulnerable-package` we can say that `builder` is
# the origin that needs to be remediated but we cannot say from the contextual
# SBOM where it was copied (parent or component in the first example or parent
# or grandparent in the second).
#
# Duplicate intermediate image packages are disallowed. The runtime safeguard
# is implemented in `builder.DocumentIndexOCI.ensure_intermediate_image_package`:
# an intermediate that was inherited when the current builder-contextualization
# document was created cannot be reused for the current builder; contextualization
# fails instead of silently reusing it.
# `allows_multiple_relationships_per_endpoint=False` remains a defensive
# per-document check in the parent collector. The runtime safeguard prevents
# this collision in a normally constructed contextualization chain, but the
# collector can still detect it in malformed or externally produced parent SBOMs.
#
# The restriction is needed because intermediate content is part of a concrete
# built stage (component, parent, or grandparent in the examples), not part of
# the builder image. I.e., if the same `builder-intermediate` identity represents
# both parent and component stages, the relationship cascade
# `builder-intermediate CONTAINS vulnerable-package`,
# `builder-intermediate DESCENDANT_OF builder`, and
# `builder BUILD_TOOL_OF parent` plus `builder BUILD_TOOL_OF component`
# cannot identify the concrete source stage of the vulnerable package.
#
# TO DO: Intermediate packages, and ideally also builder packages, need unique SPDX
# IDs within the ancestor chain while preserving their image identity. The
# copied content must remain correctly attributed to them.
#
# Note: Reusing the same builder image in multiple stages of one image does not
# create duplicate builder packages or `BUILD_TOOL_OF` relationships before
# contextualization. The non-contextual workflow deduplicates builder images by
# digest and preserves every stage annotation on the single package. During
# builder contextualization, one derived intermediate package is created per
# builder in the current component SBOM.

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
