"""Package with static definitions related to oci-image."""

from dataclasses import dataclass
from enum import Enum

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
