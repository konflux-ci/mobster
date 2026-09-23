"""Package with static definitions related to oci-image."""

from dataclasses import dataclass
from enum import Enum

from spdx_tools.spdx.model.relationship import RelationshipType

from mobster.cmd.generate.oci_image.spdx_utils import (
    AnnotationAncestorImage,
    AnnotationBaseImage,
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
    """

    name: str
    relationship_type: RelationshipType
    relationship_end: RelationshipEnd
    annotation_type: type[AnnotationBaseImage] | type[AnnotationAncestorImage] | None


# Example in parent SBOM:
# parent DESCENDANT_OF grandparent (grandparent is annotated is_base_image in
# the downloaded parent SBOM - it is the parent's parent)
BASE_IMAGE = ContentKind(
    "base image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.TARGET,
    AnnotationBaseImage,
)
# Example in parent SBOM:
# grandparent DESCENDANT_OF grandgrandparent (deeper ancestor present if the
# parent is contextualized)
ANCESTOR_IMAGE = ContentKind(
    "ancestor image",
    RelationshipType.DESCENDANT_OF,
    RelationshipEnd.TARGET,
    AnnotationAncestorImage,
)
# Example in parent SBOM:
# legacy grandparent BUILD_TOOL_OF parent (grandparent from pre-mobster era,
# annotated also as is_base_image)
LEGACY_BASE_IMAGE = ContentKind(
    "legacy base image",
    RelationshipType.BUILD_TOOL_OF,
    RelationshipEnd.SUBJECT,
    AnnotationBaseImage,
)
# component CONTAINS package (plain content package, no annotation type)
CONTENT_PACKAGE = ContentKind(
    "content package", RelationshipType.CONTAINS, RelationshipEnd.TARGET, None
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
