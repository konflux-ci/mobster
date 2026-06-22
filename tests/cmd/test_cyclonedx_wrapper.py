from typing import Any
from unittest.mock import MagicMock

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL

from mobster.cmd.cyclonedx_wrapper import CycloneDX1BomWrapper


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
def test_get_component_dicts(
    input_components: list[Component], expected_dicts: list[dict[str, Any]]
) -> None:
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
    assert sbom_obj.sbom.metadata.manufacturer is not None
    assert sbom_obj.sbom.metadata.manufacturer.name == "Red Hat"
    sbom_regenerated_dict = sbom_obj.to_dict()
    for key in sbom:
        assert key in sbom_regenerated_dict
        assert sbom[key] == sbom_regenerated_dict[key]


@pytest.mark.parametrize(
    ["sbom_model_card"],
    [
        (
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "foo",
                        "type": "library",
                        "purl": "pkg:generic/foo/bar",
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": "1",
                            }
                        ],
                        "name": "foo",
                        "modelCard": {
                            "modelParameters": {
                                "task": "text-generation",
                                "modelArchitecture": "foo",
                                "datasets": [
                                    {
                                        "type": "dataset",
                                        "name": "foo1",
                                        "contents": {"url": "foo1.com"},
                                    },
                                    {
                                        "type": "dataset",
                                        "name": "foo2",
                                        "contents": {"url": "foo2.com"},
                                    },
                                    {
                                        "type": "dataset",
                                        "name": "foo3",
                                        "contents": {"url": "foo3.com"},
                                    },
                                ],
                                "inputs": [{"format": "string"}],
                                "outputs": [{"format": "string"}],
                            },
                            "properties": [
                                {"name": "foo1", "value": "bar1"},
                                {"name": "foo2", "value": "bar2"},
                                {"name": "foo3", "value": "bar3"},
                            ],
                        },
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
def test_with_one_model_card(sbom_model_card: dict[str, Any]) -> None:
    sbom_obj = CycloneDX1BomWrapper.from_dict(sbom_model_card)
    sbom_regenerated_dict = sbom_obj.to_dict()

    for key in sbom_model_card:
        assert key in sbom_regenerated_dict
        assert sbom_model_card[key] == sbom_regenerated_dict[key]


def test_add_back_model_card() -> None:
    """Test add_back_model_card adds model cards from raw SBOM to wrapper."""
    from mobster.sbom.enrich import add_back_model_card

    mock_sbom_wrapper = MagicMock(spec=CycloneDX1BomWrapper)

    # Create mock components
    mock_component = MagicMock(spec=Component)
    mock_sbom_wrapper.sbom = MagicMock(spec=Bom)
    mock_sbom_wrapper.sbom.components = [mock_component]

    # Create raw SBOM with modelCard
    raw_sbom = {
        "components": [
            {
                "name": "test-component",
                "modelCard": {
                    "modelParameters": {"task": "text-generation"},
                    "properties": [{"name": "test", "value": "value"}],
                },
            }
        ]
    }

    add_back_model_card(mock_sbom_wrapper, raw_sbom)

    assert mock_component.model_card == raw_sbom["components"][0]["modelCard"]


def test_add_back_model_card_no_model_card() -> None:
    """Test add_back_model_card when raw SBOM has no modelCard."""
    from mobster.sbom.enrich import add_back_model_card

    mock_sbom_wrapper = MagicMock(spec=CycloneDX1BomWrapper)
    mock_component = MagicMock(spec=Component)
    mock_sbom_wrapper.sbom = MagicMock(spec=Bom)
    mock_sbom_wrapper.sbom.components = [mock_component]

    raw_sbom = {"components": [{"name": "test-component"}]}

    # This should not raise an error
    add_back_model_card(mock_sbom_wrapper, raw_sbom)

    # model_card should not be set if it wasn't in raw_sbom
    assert (
        not hasattr(mock_component, "model_card") or mock_component.model_card is None
    )
