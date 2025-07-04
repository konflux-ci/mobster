from typing import Any

import pytest
from cyclonedx.model.component import BomRef, Component, ComponentType
from packageurl import PackageURL

from mobster.cmd.generate.oci_image import CycloneDX1BomWrapper


@pytest.mark.parametrize(
    ["input_components", "expected_dicts"],
    [
        (
            [Component(name="foo", bom_ref=BomRef("1"), type=ComponentType.CONTAINER)],
            [{"name": "foo", "bom-ref": "1", "type": "container"}],
        ),
        (
            [
                Component(
                    name="foo", bom_ref=BomRef("1"), type=ComponentType.CONTAINER
                ),
                Component(
                    name="bar",
                    bom_ref=BomRef("2"),
                    type=ComponentType.LIBRARY,
                    purl=PackageURL(
                        type="rpm", version="1", name="the-rpm-of-all-arts"
                    ),
                ),
            ],
            [
                {"name": "foo", "bom-ref": "1", "type": "container"},
                {
                    "name": "bar",
                    "bom-ref": "2",
                    "type": "library",
                    "purl": "pkg:rpm/the-rpm-of-all-arts@1",
                },
            ],
        ),
    ],
)
def test_get_component_dicts(input_components, expected_dicts):
    assert CycloneDX1BomWrapper.get_component_dicts(input_components) == expected_dicts


@pytest.mark.parametrize(
    ["sbom"],
    [
        (
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "foo",
                        "type": "library",
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": "1",
                            }
                        ],
                        "name": "foo",
                    }
                ],
            },
        ),
        (
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "foo",
                        "type": "library",
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": "1",
                            }
                        ],
                        "name": "foo",
                    }
                ],
                "formulation": [
                    {
                        "components": [
                            {
                                "bom-ref": "bar",
                                "type": "library",
                                "hashes": [
                                    {
                                        "alg": "SHA-256",
                                        "content": "2",
                                    }
                                ],
                                "name": "bar",
                            }
                        ]
                    }
                ],
            },
        ),
    ],
)
def test_cdx_wrapper_to_and_from_dict(sbom: dict[str, Any]) -> None:
    sbom_obj = CycloneDX1BomWrapper.from_dict(sbom)
    sbom_regenerated_dict = sbom_obj.to_dict()
    for key in sbom:
        assert key in sbom_regenerated_dict
        assert sbom[key] == sbom_regenerated_dict[key]
