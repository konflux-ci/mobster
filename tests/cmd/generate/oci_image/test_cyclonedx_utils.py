from typing import Any

import pytest
from cyclonedx.model import Property
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL

from mobster import get_mobster_version
from mobster.cmd.generate.oci_image.cyclonedx_utils import (
    CycloneDX1BomWrapper,
    extend_cdx_with_base_images,
    get_cdx_components_from_base_images,
)
from mobster.image import Image


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["base_images_refs", "base_images", "expected_output"],
    [
        pytest.param(
            ["alpine:3.10", None, "foobar:v1", "alpine:3.10"],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10", "sha256:1"
                ),
                "foobar:v1": Image.from_image_index_url_and_digest(
                    "foobar:v1", "sha256:2"
                ),
            },
            [
                Component(
                    bom_ref=BomRef(
                        "BomRef.foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e"
                    ),
                    name="foobar",
                    version="v1",
                    type=ComponentType.CONTAINER,
                    properties=[
                        Property(
                            name="konflux:container:is_builder_image:for_stage",
                            value="2",
                        )
                    ],
                    purl=PackageURL(
                        type="oci",
                        name="foobar",
                        version="sha256:2",
                        qualifiers={"repository_url": "foobar"},
                    ),
                ),
                Component(
                    bom_ref=BomRef(
                        "BomRef.alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9"
                    ),
                    name="alpine",
                    version="3.10",
                    type=ComponentType.CONTAINER,
                    properties=[
                        Property(
                            name="konflux:container:is_builder_image:for_stage",
                            value="0",
                        ),
                        Property(name="konflux:container:is_base_image", value="true"),
                    ],
                    purl=PackageURL(
                        type="oci",
                        name="alpine",
                        version="sha256:1",
                        qualifiers={"repository_url": "alpine"},
                    ),
                ),
            ],
            id="4 Stages, Stage 1 is FROM SCRATCH and 4th Stage is the same as Stage 0",
        ),
    ],
)
async def test_get_cdx_components_from_base_images(
    base_images_refs: list[str | None],
    base_images: dict[str, Image],
    expected_output: list[Component],
) -> None:
    components = await get_cdx_components_from_base_images(
        base_images_refs, base_images
    )
    for idx, actual_component in enumerate(components):
        for attr in ("name", "version", "type", "properties", "purl"):
            assert getattr(actual_component, attr) == getattr(
                expected_output[idx], attr
            )
        # Bom-refs cannot be compared directly. If the reference does not point
        # to the same object, the comparison will evaluate as `False`
        assert actual_component.bom_ref.value == expected_output[idx].bom_ref.value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["input_sbom_dict", "base_image_refs", "base_images", "expected_sbom"],
    [
        (
            {
                "metadata": {
                    "component": {
                        "bom-ref": "BomRef.base",
                        "hashes": [{"alg": "SHA-256", "content": "1"}],
                        "name": "base",
                        "purl": "pkg:oci/base@sha256:1?"
                        "repository_url=quay.io/example/base",
                        "type": "container",
                        "version": "1.0",
                    },
                    "timestamp": "1970-01-01T00:00:00.000000+00:00",
                },
                "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "version": 1,
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "BomRef.pkg",
                        "hashes": [{"alg": "SHA-256", "content": "2"}],
                        "name": "pkg",
                        "purl": "pkg:oci/pkg@sha256:2?"
                        "repository_url=quay.io/example/pkg",
                        "type": "container",
                        "version": "2.0",
                    },
                ],
                "dependencies": [{"ref": "BomRef.base", "dependsOn": ["BomRef.pkg"]}],
            },
            [None, "alpine:3.10", "foobar:v1"],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10", "sha256:1"
                ),
                "foobar:v1": Image.from_image_index_url_and_digest(
                    "foobar:v1", "sha256:2"
                ),
            },
            {
                "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
                "metadata": {
                    "component": {
                        "bom-ref": "BomRef.base",
                        "hashes": [{"alg": "SHA-256", "content": "1"}],
                        "name": "base",
                        "purl": "pkg:oci/base@sha256:1?"
                        "repository_url=quay.io/example/base",
                        "type": "container",
                        "version": "1.0",
                    },
                    "manufacturer": {"name": "Red Hat"},
                    "timestamp": "1970-01-01T00:00:00+00:00",
                    "tools": {
                        "components": [
                            {
                                "name": "Mobster",
                                "type": "application",
                                "version": get_mobster_version(),
                            }
                        ]
                    },
                },
                "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "version": 1,
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "BomRef.pkg",
                        "hashes": [{"alg": "SHA-256", "content": "2"}],
                        "name": "pkg",
                        "purl": "pkg:oci/pkg@sha256:2?"
                        "repository_url=quay.io/example/pkg",
                        "type": "container",
                        "version": "2.0",
                    },
                ],
                "dependencies": [
                    {"ref": "BomRef.base", "dependsOn": ["BomRef.pkg"]},
                    {"ref": "BomRef.pkg"},
                ],
                "formulation": [
                    {
                        "components": [
                            {
                                "bom-ref": "BomRef.alpine-"
                                "204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                                "hashes": [
                                    {
                                        "alg": "SHA-256",
                                        "content": "1",
                                    },
                                ],
                                "name": "alpine",
                                "properties": [
                                    {
                                        "name": "konflux:container:is_builder_image:"
                                        "for_stage",
                                        "value": "1",
                                    },
                                ],
                                "purl": "pkg:oci/alpine@sha256:1?repository_url=alpine",
                                "type": "container",
                                "version": "3.10",
                            },
                            {
                                "bom-ref": "BomRef."
                                "foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e",
                                "hashes": [
                                    {
                                        "alg": "SHA-256",
                                        "content": "2",
                                    },
                                ],
                                "name": "foobar",
                                "properties": [
                                    {
                                        "name": "konflux:container:is_base_image",
                                        "value": "true",
                                    },
                                ],
                                "purl": "pkg:oci/foobar@sha256:2?repository_url=foobar",
                                "type": "container",
                                "version": "v1",
                            },
                        ]
                    }
                ],
            },
        )
    ],
)
async def test_extend_cdx_with_base_images(
    input_sbom_dict: dict[str, Any],
    base_image_refs: list[str | None],
    base_images: dict[str, Image],
    expected_sbom: dict[str, Any],
) -> None:
    initial_sbom = CycloneDX1BomWrapper.from_dict(input_sbom_dict)
    await extend_cdx_with_base_images(initial_sbom, base_image_refs, base_images)
    updated_sbom_dict = initial_sbom.to_dict()
    assert updated_sbom_dict == expected_sbom
