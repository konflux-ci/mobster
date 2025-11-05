"""Package with static definitions related to oci-image."""

from dataclasses import dataclass
from enum import Enum

HERMETO_ANNOTATION_COMMENTS = [
    '{"name": "cachi2:found_by", "value": "cachi2"}',
    '{"name": "hermeto:found_by", "value": "hermeto"}',
]


class PackageProducer(str, Enum):
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


class MatchBy(str, Enum):
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
