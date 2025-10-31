import datetime
from typing import Any
from unittest.mock import MagicMock, call, patch

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

from mobster.cmd.generate.oci_image.contextual_sbom.match_utils import (
    ComponentPackageIndex,
    checksums_match,
    generated_by_hermeto,
    package_matched,
    validate_and_compare_purls,
)


@pytest.mark.parametrize(
    ["identifier_type", "identifier_value", "should_index"],
    [
        ("checksum", "abc123", True),
        ("verification_code", "vc123", True),
        ("purl_with_version", "pkg:npm/package@1.0.0", True),
        ("purl_no_version", "pkg:npm/package", False),
        ("purl_invalid", "invalid-format", False),
        ("none", "", False),
    ],
)
def test_component_package_index_all_identifiers(
    identifier_type: str, identifier_value: str, should_index: bool
) -> None:
    """
    Test ComponentPackageIndex handles all identifier types and edge cases.
    """
    component_pkg_kwargs: dict[str, Any] = {
        "spdx_id": "SPDXRef-test",
        "name": "test-pkg",
        "download_location": SpdxNoAssertion(),
    }
    parent_pkg_kwargs: dict[str, Any] = {
        "spdx_id": "SPDXRef-parent",
        "name": "test-pkg",
        "download_location": SpdxNoAssertion(),
    }

    if identifier_type == "checksum":
        component_pkg_kwargs["checksums"] = [
            Checksum(ChecksumAlgorithm.SHA256, identifier_value)
        ]
        parent_pkg_kwargs["checksums"] = [
            Checksum(ChecksumAlgorithm.SHA256, identifier_value)
        ]
    elif identifier_type == "verification_code":
        component_pkg_kwargs["verification_code"] = PackageVerificationCode(
            value=identifier_value
        )
        parent_pkg_kwargs["verification_code"] = PackageVerificationCode(
            value=identifier_value
        )
    elif identifier_type.startswith("purl"):
        component_pkg_kwargs["external_references"] = [
            ExternalPackageRef(
                ExternalPackageRefCategory.PACKAGE_MANAGER, "purl", identifier_value
            )
        ]
        parent_pkg_kwargs["external_references"] = [
            ExternalPackageRef(
                ExternalPackageRefCategory.PACKAGE_MANAGER, "purl", identifier_value
            )
        ]
    # none: packages are missing unique identifiers

    pkg: Package = Package(**component_pkg_kwargs)
    parent_pkg: Package = Package(**parent_pkg_kwargs)
    rel = Relationship("SPDXRef-component", RelationshipType.CONTAINS, "SPDXRef-test")
    index = ComponentPackageIndex([(pkg, rel)])

    # Verify index population based on identifier type
    if identifier_type == "checksum":
        assert len(index.checksum_index) == (1 if should_index else 0)
        assert len(index.verification_code_index) == 0
        assert len(index.purl_index) == 0
    elif identifier_type == "verification_code":
        assert len(index.checksum_index) == 0
        assert len(index.verification_code_index) == (1 if should_index else 0)
        assert len(index.purl_index) == 0
    else:  # purl_* or none
        assert len(index.checksum_index) == 0
        assert len(index.verification_code_index) == 0
        assert len(index.purl_index) == (1 if should_index else 0)

    # Verify find_candidates
    candidates = index.find_candidates(parent_pkg)
    assert len(candidates) == (1 if should_index else 0)
    if should_index:
        assert candidates[0] == (pkg, rel)


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.contextual_sbom.contextualize.package_matched")
async def test_skip_already_matched_component_package(
    mock_package_matched: MagicMock,
) -> None:
    """
    Test that already matched component packages are skipped.
    When parent contains duplicate packages (packages with same "unique" id)
    package_matched() should be called only once.
    The second parent package finds the same
    candidate but skips it because it's already matched.
    """
    from mobster.cmd.generate.oci_image.contextual_sbom.contextualize import (
        map_parent_to_component_and_modify_component,
    )

    shared_checksum = Checksum(ChecksumAlgorithm.SHA256, "duplicate123")
    parent_spdx_id = "SPDXRef-parent-from-component"

    # Parent SBOM: 2 duplicate packages with same checksum
    parent_sbom_doc = MagicMock(spec=Document)
    parent_root = Package("SPDXRef-parent", "parent", SpdxNoAssertion())
    parent_pkg_1 = Package(
        "SPDXRef-p1", "duplicate-pkg", SpdxNoAssertion(), checksums=[shared_checksum]
    )
    parent_pkg_2 = Package(
        "SPDXRef-p2", "duplicate-pkg", SpdxNoAssertion(), checksums=[shared_checksum]
    )

    parent_sbom_doc.packages = [parent_root, parent_pkg_1, parent_pkg_2]
    parent_sbom_doc.relationships = [
        Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-parent"),
        Relationship("SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-p1"),
        Relationship("SPDXRef-parent", RelationshipType.CONTAINS, "SPDXRef-p2"),
    ]
    parent_sbom_doc.annotations = []

    # Component SBOM: 1 package with matching checksum
    component_sbom_doc = MagicMock(spec=Document)
    component_root = Package("SPDXRef-component", "component", SpdxNoAssertion())
    component_pkg = Package(
        "SPDXRef-c1", "duplicate-pkg", SpdxNoAssertion(), checksums=[shared_checksum]
    )

    component_sbom_doc.packages = [component_root, component_pkg]
    component_sbom_doc.relationships = [
        Relationship(
            "SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-component"
        ),
        Relationship(
            "SPDXRef-component", RelationshipType.DESCENDANT_OF, parent_spdx_id
        ),
        Relationship("SPDXRef-component", RelationshipType.CONTAINS, "SPDXRef-c1"),
    ]
    component_sbom_doc.annotations = []

    mock_package_matched.return_value = True
    await map_parent_to_component_and_modify_component(
        parent_sbom_doc, component_sbom_doc, parent_spdx_id, []
    )

    assert mock_package_matched.call_count == 1, (
        f"Expected package_matched called 1 time, "
        f"got {mock_package_matched.call_count}. "
    )


@pytest.mark.parametrize(
    ["parent_checksums", "component_checksums", "expected_result"],
    [
        # Successful matches for all checksums
        pytest.param(
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA256, "xyz789"),
            ],
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA256, "xyz789"),
            ],
            True,
            id="successful-matches",
        ),
        pytest.param(
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA1, "xyz789"),
            ],
            [
                Checksum(ChecksumAlgorithm.SHA256, "different123"),
                Checksum(ChecksumAlgorithm.MD5, "different456"),
            ],
            False,
            id="no-matches",
        ),
        pytest.param(
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA1, "xyz789"),
            ],
            [
                Checksum(ChecksumAlgorithm.SHA256, "abc123def456"),
                Checksum(ChecksumAlgorithm.SHA1, "xyz789"),
                Checksum(ChecksumAlgorithm.MD5, "different"),
            ],
            False,
            id="some-common-items-but-not-all-match",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [],
            False,
            id="one-empty-list",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA1, "abc123def456")],
            False,
            id="different-algorithms-same-value",
        ),
    ],
)
def test_checksums_match(
    parent_checksums: list[Checksum],
    component_checksums: list[Checksum],
    expected_result: bool,
) -> None:
    assert checksums_match(parent_checksums, component_checksums) is expected_result


@pytest.mark.parametrize(
    ["component_purl", "parent_purl", "expected_result"],
    [
        # Successful validation, required fields and namespace match, qualifiers ignored
        pytest.param(
            "pkg:npm/test-namespace/test-package@1.0.0?arch=amd64&distro=fedora&os=linux&checksum=sha256:abc123",
            "pkg:npm/test-namespace/test-package@1.0.0?arch=x86_64&distro=ubuntu&os=linux&checksum=sha256:def456",
            True,
            id="successful-validation",
        ),
        pytest.param(
            "pkg:npm/test-namespace/test-package@1.0.0",
            "pkg:npm/test-package@1.0.0",
            False,
            id="namespace-missing",
        ),
        pytest.param(
            "pkg:npm/test-namespace/test-package@1.0.0",
            "pkg:npm/different-namespace/test-package@1.0.0",
            False,
            id="namespace-mismatch",
        ),
        pytest.param(
            "invalid-purl", "pkg:npm/test-package@1.0.0", False, id="invalid-format"
        ),
        pytest.param(
            "pkg:npm@1.0.0", "pkg:npm/test-package@1.0.0", False, id="missing-name"
        ),
        pytest.param(
            "pkg:npm/test-package",
            "pkg:npm/test-package@1.0.0",
            False,
            id="missing-version",
        ),
        pytest.param("", "pkg:npm/test-package@1.0.0", False, id="empty-string-one"),
        pytest.param("", "", False, id="empty-string-both"),
        pytest.param(
            None, "pkg:npm/test-package@1.0.0", False, id="none-component-purl"
        ),
        pytest.param("pkg:npm/test-package@1.0.0", None, False, id="none-parent-purl"),
        pytest.param(None, None, False, id="none-both"),
    ],
)
def test_validate_and_compare_purls(
    component_purl: str, parent_purl: str, expected_result: bool
) -> None:
    assert validate_and_compare_purls(component_purl, parent_purl) == expected_result


@pytest.mark.parametrize(
    ["annotations", "expected_result"],
    [
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "cachi2"),
                    datetime.datetime.now(),
                    '{"name": "cachi2:found_by", "value": "cachi2"}',
                ),
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "other-tool"),
                    datetime.datetime.now(),
                    '{"name": "other-tool:found_by", "value": "other-tool"}',
                ),
            ],
            True,
            id="cachi2-detection",
        ),
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "hermeto"),
                    datetime.datetime.now(),
                    '{"name": "hermeto:found_by", "value": "hermeto"}',
                ),
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "other-tool"),
                    datetime.datetime.now(),
                    '{"name": "other-tool:found_by", "value": "other-tool"}',
                ),
            ],
            True,
            id="hermeto-detection",
        ),
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.TOOL, "other-tool"),
                    datetime.datetime.now(),
                    '{"name": "other-tool:found_by", "value": "other-tool"}',
                ),
            ],
            False,
            id="non-hermeto-detection",
        ),
        pytest.param(
            [
                Annotation(
                    "SPDXRef-annotation",
                    AnnotationType.OTHER,
                    Actor(ActorType.PERSON, "user"),
                    datetime.datetime.now(),
                    '{"name": "cachi2:found_by", "value": "cachi2"}',
                ),
            ],
            False,
            id="wrong-actor-type",
        ),
        pytest.param(
            [],
            False,
            id="empty-annotations",
        ),
    ],
)
def test_generated_by_hermeto(
    annotations: list[Annotation], expected_result: bool
) -> None:
    assert generated_by_hermeto(annotations) is expected_result


@pytest.mark.parametrize(
    ["purls_match", "expected_result"],
    [
        (True, True),
        (False, False),
    ],
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.match_utils.get_annotations_by_spdx_id"
)
@patch("mobster.cmd.generate.oci_image.contextual_sbom.match_utils.get_package_purl")
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.match_utils.validate_and_compare_purls"
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.match_utils.generated_by_hermeto"
)
def test_package_matched_hermeto_to_syft(
    mock_generated_by_hermeto: MagicMock,
    mock_validate_and_compare_purls: MagicMock,
    mock_get_package_purl: MagicMock,
    mock_get_annotations_by_spdx_id: MagicMock,
    purls_match: bool,
    expected_result: bool,
) -> None:
    """Test package matching for hermeto-generated packages."""
    mock_validate_and_compare_purls.return_value = purls_match
    mock_generated_by_hermeto.return_value = True

    parent_doc = MagicMock(spec=Document)
    parent_package = MagicMock(spec=Package)
    component_package = MagicMock(spec=Package)

    result = package_matched(parent_doc, parent_package, component_package)

    mock_get_annotations_by_spdx_id.assert_called_once_with(
        parent_doc, parent_package.spdx_id
    )
    mock_get_package_purl.assert_has_calls(
        [
            call(parent_package),
            call(component_package),
        ]
    )
    mock_validate_and_compare_purls.assert_called_once()
    mock_generated_by_hermeto.assert_called_once()

    assert result is expected_result


@pytest.mark.parametrize(
    [
        "parent_checksums",
        "component_checksums",
        "parent_verification_code",
        "component_verification_code",
        "purls_match",
        "expected_result",
    ],
    [
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            PackageVerificationCode(value="abc123"),
            PackageVerificationCode(value="different123"),
            False,
            True,
            id="checksums-match-others-mismatch",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            None,
            None,
            False,
            True,
            id="checksums-match-others-missing",
        ),
        pytest.param(
            [],
            [],
            PackageVerificationCode(value="abc123"),
            PackageVerificationCode(value="abc123"),
            False,
            True,
            id="only-verification-codes-match",
        ),
        pytest.param(
            [],
            [],
            None,
            None,
            True,
            True,
            id="only-purls-match",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [Checksum(ChecksumAlgorithm.SHA256, "different123def456")],
            PackageVerificationCode(value="abc123"),
            PackageVerificationCode(value="abc123"),
            True,
            False,
            id="checksums-mismatch-others-match",
        ),
        pytest.param(
            [Checksum(ChecksumAlgorithm.SHA256, "abc123def456")],
            [],
            PackageVerificationCode(value="abc123"),
            None,
            True,
            False,
            id="one-checksum-and-one-verification-code-missing-purls-match",
        ),
        pytest.param(
            [],
            [],
            None,
            None,
            False,
            False,
            id="checksums-and-verification-codes-missing-purls-mismatch",
        ),
    ],
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.match_utils.get_annotations_by_spdx_id"
)
@patch("mobster.cmd.generate.oci_image.contextual_sbom.match_utils.get_package_purl")
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.match_utils.validate_and_compare_purls"
)
@patch(
    "mobster.cmd.generate.oci_image.contextual_sbom.match_utils.generated_by_hermeto"
)
def test_package_matched_syft_to_syft(
    mock_generated_by_hermeto: MagicMock,
    mock_validate_and_compare_purls: MagicMock,
    mock_get_package_purl: MagicMock,
    mock_get_annotations_by_spdx_id: MagicMock,
    parent_checksums: list[Checksum],
    component_checksums: list[Checksum],
    parent_verification_code: PackageVerificationCode,
    component_verification_code: PackageVerificationCode,
    purls_match: bool,
    expected_result: bool,
) -> None:
    mock_validate_and_compare_purls.return_value = purls_match
    mock_generated_by_hermeto.return_value = False

    parent_doc = MagicMock(spec=Document)
    parent_package = MagicMock(spec=Package)
    parent_package.checksums = parent_checksums
    parent_package.verification_code = parent_verification_code
    component_package = MagicMock(spec=Package)
    component_package.checksums = component_checksums
    component_package.verification_code = component_verification_code

    result = package_matched(parent_doc, parent_package, component_package)

    mock_get_package_purl.assert_has_calls(
        [
            call(parent_package),
            call(component_package),
        ]
    )
    mock_generated_by_hermeto.assert_called_once()

    assert result is expected_result
