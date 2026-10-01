from typing import Any
from unittest.mock import patch

import pytest
from spdx_tools.spdx.model.document import CreationInfo
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion

from mobster.image import Image
from mobster.sbom import spdx


@pytest.mark.parametrize(
    ["actor", "expected_output"],
    [
        ("foo", "Tool: foo"),
        ("Tool: foo", "Tool: foo"),
        ("Person: foo", "Person: foo"),
        ("Organization: foo", "Organization: foo"),
        ("NOASSERTION", "NOASSERTION"),
    ],
)
def test_normalize_actor(actor: str, expected_output: str) -> None:
    assert spdx.normalize_actor(actor) == expected_output


@pytest.mark.parametrize(
    ["input_package_dict", "expected_output_dict"],
    [
        (
            {"SPDXID": "SPDXRef-foo"},
            {"SPDXID": "SPDXRef-foo", "downloadLocation": "NOASSERTION", "name": ""},
        ),
        (
            {
                "name": "foo",
                "supplier": "bar",
            },
            {
                "name": "foo",
                "supplier": "Tool: bar",
                "downloadLocation": "NOASSERTION",
            },
        ),
    ],
)
def test_normalize_package(
    input_package_dict: dict[str, Any], expected_output_dict: dict[str, Any]
) -> None:
    package_dict = input_package_dict.copy()
    spdx.normalize_package(package_dict)
    assert package_dict == expected_output_dict


@pytest.mark.parametrize(
    ["input_sbom_dict", "expected_sbom_dict"],
    [
        (
            {"packages": [{"SPDXID": "SPDXRef-foo"}]},
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "dataLicense": "CC0-1.0",
                "spdxVersion": "SPDX-2.3",
                "documentNamespace": "https://konflux-ci.dev/spdxdocs/"
                "MOBSTER:UNFILLED_NAME (please update this field)-1",
                "name": "MOBSTER:UNFILLED_NAME (please update this field)",
                "creationInfo": {
                    "created": "1970-01-01T00:00:00Z",
                    "creators": [
                        spdx.get_red_hat_org_string(),
                        spdx.get_mobster_tool_string(),
                    ],
                },
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "downloadLocation": "NOASSERTION",
                        "name": "",
                    }
                ],
            },
        )
    ],
)
def test_normalize_sbom(
    input_sbom_dict: dict[str, Any],
    expected_sbom_dict: dict[str, Any],
) -> None:
    with patch("mobster.sbom.spdx.uuid4") as mock_uuid:
        mock_uuid.return_value = 1
        sbom_dict = input_sbom_dict.copy()
        spdx.normalize_sbom(sbom_dict)
        assert sbom_dict == expected_sbom_dict


def test_get_package() -> None:
    mock_image = Image.from_image_index_url_and_digest(
        "registry/repo:tag", "sha256:1234567890abcdef"
    )
    result = spdx.get_image_package(mock_image, "fake_spdx_id")

    assert isinstance(result, Package)
    assert result.spdx_id == "fake_spdx_id"
    assert result.name == mock_image.name
    assert result.checksums[0].value == mock_image.digest_hex_val


def test_get_creation_info() -> None:
    result = spdx.get_creation_info("foo-bar")

    assert isinstance(result, CreationInfo)
    assert result.spdx_id == "SPDXRef-DOCUMENT"


def test_deduplicate_relationships() -> None:
    string_rel_a = Relationship(
        spdx_element_id="SPDXRef-root",
        relationship_type=RelationshipType.CONTAINS,
        related_spdx_element_id="SPDXRef-pkg-a",
        comment=None,
    )
    string_rel_b = Relationship(
        spdx_element_id="SPDXRef-root",
        relationship_type=RelationshipType.CONTAINS,
        related_spdx_element_id="SPDXRef-pkg-a",
        comment=None,
    )
    string_rel_different_comment = Relationship(
        spdx_element_id="SPDXRef-root",
        relationship_type=RelationshipType.CONTAINS,
        related_spdx_element_id="SPDXRef-pkg-a",
        comment="kept because comment differs",
    )
    noassertion_rel_a = Relationship(
        spdx_element_id="SPDXRef-root",
        relationship_type=RelationshipType.CONTAINS,
        related_spdx_element_id=SpdxNoAssertion(),
        comment=None,
    )
    noassertion_rel_b = Relationship(
        spdx_element_id="SPDXRef-root",
        relationship_type=RelationshipType.CONTAINS,
        related_spdx_element_id=SpdxNoAssertion(),
        comment=None,
    )

    relationships = [
        string_rel_a,
        string_rel_b,
        string_rel_different_comment,
        noassertion_rel_a,
        noassertion_rel_b,
    ]

    result = spdx.deduplicate_relationships(relationships)

    assert result == [string_rel_a, string_rel_different_comment, noassertion_rel_a]
