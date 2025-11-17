import datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackageVerificationCode,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.cmd.generate.oci_image.contextual_sbom.constants import (
    MatchBy,
    PackageInfo,
    PackageMatchInfo,
    PackageProducer,
)


def get_base_image_items(
    spdx_element_id: str,
    related_spdx_element_id: str,
    legacy: bool,
    grandparent: bool = False,
) -> tuple[Package, Annotation, Relationship]:
    """
    Helper function to generate image package with DESCENDANT_OF
    or BUILD_TOOL_OF relationship and appropriate annotation.
    """
    if legacy and grandparent:
        raise ValueError("Legacy SBOMs do not bear grandparents.")

    # Relationship
    if legacy:
        rel = RelationshipType.BUILD_TOOL_OF
        rel_args = (spdx_element_id, rel, related_spdx_element_id)
    else:
        rel = RelationshipType.DESCENDANT_OF
        rel_args = (related_spdx_element_id, rel, spdx_element_id)
    relationship = Relationship(*rel_args)

    # Annotation
    suffix = "is_ancestor_image" if grandparent else "is_base_image"
    annotation_comment = f'{{"name": "konflux:container:{suffix}",   "value": "true" }}'

    annotation = Annotation(
        spdx_element_id,
        AnnotationType.OTHER,
        Actor(ActorType.TOOL, "ham"),
        datetime.datetime.now(),
        annotation_comment,
    )

    # Package
    package = Package(spdx_element_id, "name", SpdxNoAssertion())

    return package, annotation, relationship


def get_root_package_items(spdx_id: str) -> tuple[Package, Relationship]:
    """Helper function to generate root package and relationship items."""
    return Package(spdx_id, "name", SpdxNoAssertion()), Relationship(
        "SPDXRef-DOCUMENT",
        RelationshipType.DESCRIBES,
        spdx_id,
    )


@pytest.fixture
def mock_doc() -> MagicMock:
    """Fixture for creating a mock Document with spec."""
    return MagicMock(spec=Document)


def create_package_with_identifier(
    spdx_id: str,
    identifier_type: str,
    matching_value: bool = True,
) -> Package:
    """
    Create test package with specified identifier type.

    Args:
        spdx_id: SPDX package ID
        identifier_type: One of "checksum", "verification_code", or "purl"
        matching_value: If True, use matching identifier value;
            if False, use different value

    Returns:
        Package with appropriate identifier
    """
    kwargs: dict[str, Any] = {
        "spdx_id": spdx_id,
        "name": "package",
        "download_location": SpdxNoAssertion(),
    }

    if identifier_type == "checksum":
        value = "abc123def456" if matching_value else "different456"
        kwargs["checksums"] = [Checksum(ChecksumAlgorithm.SHA256, value)]

    elif identifier_type == "verification_code":
        value = "verification123" if matching_value else "different123"
        kwargs["verification_code"] = PackageVerificationCode(value=value)

    elif identifier_type == "purl":
        version = "1.0.0" if matching_value else "2.0.0"
        kwargs["external_references"] = [
            ExternalPackageRef(
                ExternalPackageRefCategory.PACKAGE_MANAGER,
                "purl",
                f"pkg:npm/namespace/package@{version}",
            )
        ]

    return Package(**kwargs)


def create_annotation_with_spdx_id(spdx_id: str) -> Annotation:
    """Create annotation with specified SPDX ID for testing."""
    return Annotation(
        spdx_id,
        AnnotationType.OTHER,
        Actor(ActorType.TOOL, "test-tool"),
        datetime.datetime.now(),
        "test annotation",
    )


def create_package_match_info(
    parent_spdx_id: str,
    component_spdx_id: str,
    matched: bool,
    parent_producer: PackageProducer = PackageProducer.SYFT,
    component_producer: PackageProducer = PackageProducer.SYFT,
    match_by: MatchBy = MatchBy.CHECKSUM,
    identifier_value: str | None = None,
) -> PackageMatchInfo:
    """
    Create a PackageMatchInfo for testing.

    Args:
        parent_spdx_id: SPDX ID of the parent package
        component_spdx_id: SPDX ID of the component package
        matched: Whether the packages matched
        parent_producer: Tool that produced the parent package
        component_producer: Tool that produced the component package
        match_by: How the match was performed/attempted
        identifier_value: The value that matched (only used if matched=True)

    Returns:
        PackageMatchInfo with specified match result
    """
    return PackageMatchInfo(
        matched=matched,
        match_by=match_by,
        parent_info=PackageInfo(parent_spdx_id, parent_producer),
        component_info=PackageInfo(component_spdx_id, component_producer),
        identifier_value=identifier_value if matched else None,
    )
