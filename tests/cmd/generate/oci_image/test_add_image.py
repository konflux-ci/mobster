import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cyclonedx.model.bom import Bom
from spdx_tools.spdx.model.document import CreationInfo, Document

from mobster.cmd.generate.oci_image.add_image import (
    extend_sbom_with_image_reference,
    update_component_in_cyclonedx_sbom,
)
from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.image import Image
from tests.conftest import assert_cdx_sbom


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["input_sbom_dict", "image", "is_builder_image", "expected_wrapped_sbom"],
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
                        "bom-ref": "BomRef.base",
                        "hashes": [{"alg": "SHA-256", "content": "1"}],
                        "name": "base",
                        "purl": "pkg:oci/base@sha256:1?"
                        "repository_url=quay.io/example/base",
                        "type": "container",
                        "version": "1.0",
                    },
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
            Image.from_image_index_url_and_digest(
                image_tag_pullspec="foo.bar/foobar/ham:v1", image_digest="sha256:3"
            ),
            False,
            {
                "metadata": {
                    "component": {
                        "bom-ref": "BomRef.ham-"
                        "ae1b34732beb04d81a7dd66866751f28ff0a12a4eaa8965e36a0b6060d0417a2",
                        "hashes": [{"alg": "SHA-256", "content": "3"}],
                        "name": "ham",
                        "purl": "pkg:oci/ham@sha256:3?"
                        "repository_url=foo.bar/foobar/ham",
                        "type": "container",
                        "version": "v1",
                    },
                    "timestamp": "1970-01-01T00:00:00+00:00",
                },
                "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
                "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
                "version": 1,
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "BomRef.base",
                        "hashes": [{"alg": "SHA-256", "content": "1"}],
                        "name": "base",
                        "purl": "pkg:oci/base@sha256:1?"
                        "repository_url=quay.io/example/base",
                        "type": "container",
                        "version": "1.0",
                    },
                    {
                        "bom-ref": "BomRef.ham-"
                        "ae1b34732beb04d81a7dd66866751f28ff0a12a4eaa8965e36a0b6060d0417a2",
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": "3",
                            },
                        ],
                        "name": "ham",
                        "purl": "pkg:oci/ham@sha256:3?"
                        "repository_url=foo.bar/foobar/ham",
                        "type": "container",
                        "version": "v1",
                    },
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
                    {
                        "ref": "BomRef.ham-"
                        "ae1b34732beb04d81a7dd66866751f28ff0a12a4eaa8965e36a0b6060d0417a2",
                        "dependsOn": ["BomRef.base", "BomRef.pkg"],
                    },
                    {"ref": "BomRef.pkg"},
                ],
            },
        ),
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
            Image.from_image_index_url_and_digest(
                image_tag_pullspec="foo.bar/foobar/ham:v1", image_digest="sha256:3"
            ),
            True,
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
                    "timestamp": "1970-01-01T00:00:00+00:00",
                },
                "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
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
                                "bom-ref": "BomRef.ham-"
                                "ae1b34732beb04d81a7dd66866751f28ff0a12a4eaa8965e36a0b6060d0417a2",
                                "hashes": [{"alg": "SHA-256", "content": "3"}],
                                "name": "ham",
                                "purl": "pkg:oci/ham@sha256:3?"
                                "repository_url=foo.bar/foobar/ham",
                                "type": "container",
                                "version": "v1",
                                "properties": [
                                    {
                                        "name": "konflux:container:"
                                        "is_builder_image:additional_builder_image",
                                        "value": "script-runner-image",
                                    },
                                ],
                            },
                        ]
                    }
                ],
            },
        ),
    ],
)
async def test_update_component_in_cyclonedx_sbom(
    input_sbom_dict: dict[str, Any],
    image: Image,
    is_builder_image: bool,
    expected_wrapped_sbom: dict[str, Any],
) -> None:
    initial_sbom = CycloneDX1BomWrapper.from_dict(input_sbom_dict)
    await update_component_in_cyclonedx_sbom(initial_sbom, image, is_builder_image)
    updated_sbom_dict = initial_sbom.to_dict()
    assert_cdx_sbom(updated_sbom_dict, expected_wrapped_sbom)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["sbom_obj"],
    [
        (
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.bar/example",
                    created=datetime.datetime(1970, 1, 1),
                    creators=[],
                )
            ),
        ),
        (CycloneDX1BomWrapper(Bom()),),
    ],
)
@patch("mobster.cmd.generate.oci_image.add_image.update_package_in_spdx_sbom")
@patch("mobster.cmd.generate.oci_image.add_image.update_component_in_cyclonedx_sbom")
async def test_extend_sbom_with_image_reference(
    mock_update_component_in_cyclonedx_sbom: AsyncMock,
    mock_update_package_in_spdx_sbom: AsyncMock,
    sbom_obj: Document | CycloneDX1BomWrapper,
) -> None:
    await extend_sbom_with_image_reference(
        sbom_obj,
        Image.from_image_index_url_and_digest(
            image_tag_pullspec="foo.bar/foobar/ham:v1", image_digest="sha256:1"
        ),
        True,
    )
    if isinstance(sbom_obj, CycloneDX1BomWrapper):
        mock_update_component_in_cyclonedx_sbom.assert_awaited_once()
    else:
        mock_update_package_in_spdx_sbom.assert_awaited_once()
