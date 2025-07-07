import datetime
from hashlib import sha256
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cyclonedx.model.component import BomRef, Component, ComponentType, Property
from packageurl import PackageURL
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.annotation import Annotation, AnnotationType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.json.json_parser import JsonLikeDictParser

from mobster import get_mobster_version
from mobster.cmd.generate.oci_image import CycloneDX1BomWrapper
from mobster.cmd.generate.oci_image.base_images_dockerfile import (
    _extend_cdx_with_base_images,
    _extend_spdx_with_base_images,
    _get_cdx_components_from_base_images,
    _get_images_and_their_annotations,
    _get_spdx_packages_from_base_images,
    extend_sbom_with_base_images_from_dockerfile,
    get_base_images_refs_from_dockerfile,
    get_objects_for_base_images,
)
from mobster.image import Image


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["dockerfile_sample", "target_stage", "expected_list"],
    [
        (1, "", ["alpine:3.10", None]),
        (1, "build", ["alpine:3.10"]),
        (
            2,
            "",
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
                "registry.access.redhat.com/ubi9/ubi:latest",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
        ),
        (
            2,
            "nothing",
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
            ],
        ),
        (
            2,
            "foo",
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
                "registry.access.redhat.com/ubi9/ubi:latest",
            ],
        ),
        (
            2,
            "bar",
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
                "registry.access.redhat.com/ubi9/ubi:latest",
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
        ),
        (
            2,
            "registry.access.redhat.com/ubi8/ubi:latest",
            ["registry.access.redhat.com/ubi8/ubi:latest"],
        ),
    ],
)
async def test_get_base_images_refs_from_dockerfile(
    dockerfile_sample: int,
    target_stage: str,
    expected_list: list[str | None],
    sample1_parsed_dockerfile: dict[str, Any],
    sample2_parsed_dockerfile: dict[str, Any],
) -> None:
    dockerfile = (
        sample1_parsed_dockerfile
        if dockerfile_sample == 1
        else sample2_parsed_dockerfile
    )
    assert (
        await get_base_images_refs_from_dockerfile(dockerfile, target_stage)
        == expected_list
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "base_images_refs",
        "expected_outcome",
        "oras_stderr",
    ],
    [
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
                "alpine:3.10",
                None,
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10",
                    "sha256:ef437a97b47a6c00ea884fa314df3e05d542e14ef999c344e394808c2b7035d9",
                ),
                "registry.access.redhat.com/ubi8/ubi"
                ":latest": Image.from_image_index_url_and_digest(
                    "registry.access.redhat.com/ubi8/ubi:latest",
                    "sha256:f75e57db5cbc53b37a8b33a0b0b084782ddae260220d9dd8cc968eab4d579062",
                ),
            },
            b"",
        ),
        (
            [
                "registry.access.redhat.com/ubi8/ubi:latest",
            ],
            {},
            b"Uh oh, error I guess.",
        ),
    ],
)
@patch("mobster.cmd.generate.oci_image.base_images_dockerfile.run_async_subprocess")
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.make_oci_auth_file",
)
@patch("mobster.cmd.generate.oci_image.base_images_dockerfile.LOGGER")
async def test_get_objects_for_base_images(
    mock_logger: AsyncMock,
    mock_make_oci_auth_file: AsyncMock,
    mock_run_async_subprocess: AsyncMock,
    base_images_refs: list[str],
    expected_outcome: dict[str, Image],
    oras_stderr: bytes,
) -> None:
    def mocked_subprocess_calling(*args, **_) -> tuple[int, bytes, bytes]:
        digest = f"sha256:{sha256(args[0][-1].encode()).hexdigest()}\n".encode()
        return (
            (int(bool(oras_stderr))),
            digest,
            oras_stderr,
        )

    mock_run_async_subprocess.side_effect = mocked_subprocess_calling

    assert await get_objects_for_base_images(base_images_refs) == expected_outcome

    if oras_stderr:
        assert any(
            args[0].startswith("Problem getting digest of a base image")
            for args in mock_logger.warning.call_args
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["base_images_refs", "base_images", "expected_output"],
    [
        pytest.param(
            ["alpine:3.10", None, "foobar:v1"],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10", "sha256:1"
                ),
                "foobar:v1": Image.from_image_index_url_and_digest(
                    "foobar:v1", "sha256:2"
                ),
            },
            [
                (
                    Image.from_image_index_url_and_digest("alpine:3.10", "sha256:1"),
                    [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        }
                    ],
                ),
                (
                    Image.from_image_index_url_and_digest("foobar:v1", "sha256:2"),
                    [{"name": "konflux:container:is_base_image", "value": "true"}],
                ),
            ],
            id="3 Stages, Stage 1 is FROM SCRATCH",
        ),
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
                (
                    Image.from_image_index_url_and_digest("foobar:v1", "sha256:2"),
                    [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "2",  # Stage 1 is FROM SCRATCH,
                            # this value is correct.
                        },
                    ],
                ),
                (
                    Image.from_image_index_url_and_digest("alpine:3.10", "sha256:1"),
                    [
                        {
                            "name": "konflux:container:is_builder_image:for_stage",
                            "value": "0",
                        },
                        {"name": "konflux:container:is_base_image", "value": "true"},
                    ],
                ),
            ],
            id="4 Stages, Stage 1 is FROM SCRATCH and 4th Stage is the same as Stage 0",
        ),
    ],
)
async def test__get_images_and_their_annotations(
    base_images_refs: list[str],
    base_images: dict[str, Image],
    expected_output: list[tuple[Image, dict[str, str]]],
) -> None:
    assert (
        await _get_images_and_their_annotations(base_images_refs, base_images)
        == expected_output
    )


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
async def test__get_cdx_components_from_base_images(
    base_images_refs: list[str],
    base_images: dict[str, Image],
    expected_output: list[Component],
) -> None:
    components = await _get_cdx_components_from_base_images(
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
            (
                [
                    Package(
                        spdx_id="SPDXRef-image-foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e",
                        name="foobar",
                        version="v1",
                        download_location=SpdxNoAssertion(),
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION, name="Red Hat"
                        ),
                        files_analyzed=False,
                        checksums=[
                            Checksum(algorithm=ChecksumAlgorithm.SHA256, value="2")
                        ],
                        license_declared=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/foobar@sha256:2?repository_url=foobar",
                            )
                        ],
                    ),
                    Package(
                        spdx_id="SPDXRef-image-alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                        name="alpine",
                        version="3.10",
                        download_location=SpdxNoAssertion(),
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION, name="Red Hat"
                        ),
                        files_analyzed=False,
                        checksums=[
                            Checksum(algorithm=ChecksumAlgorithm.SHA256, value="1")
                        ],
                        license_declared=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/alpine@sha256:1?repository_url=alpine",
                            )
                        ],
                    ),
                ],
                [
                    Annotation(
                        spdx_id="SPDXRef-image-foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e",
                        annotation_type=AnnotationType.OTHER,
                        annotator=Actor(
                            actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                        ),
                        annotation_comment='{"name":"konflux:container:is_builder_image:for_stage","value":"2"}',
                        annotation_date=datetime.datetime(1970, 1, 1),
                    ),
                    Annotation(
                        spdx_id="SPDXRef-image-alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                        annotation_type=AnnotationType.OTHER,
                        annotator=Actor(
                            actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                        ),
                        annotation_comment='{"name":"konflux:container:is_builder_image:for_stage","value":"0"}',
                        annotation_date=datetime.datetime(1970, 1, 1),
                    ),
                    Annotation(
                        spdx_id="SPDXRef-image-alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                        annotation_type=AnnotationType.OTHER,
                        annotator=Actor(
                            actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                        ),
                        annotation_comment='{"name":"konflux:container:is_base_image","value":"true"}',
                        annotation_date=datetime.datetime(1970, 1, 1),
                    ),
                ],
            ),
            id="4 Stages, Stage 1 is FROM SCRATCH and 4th Stage is the same as Stage 0",
        ),
    ],
)
@patch("mobster.cmd.generate.oci_image.base_images_dockerfile.datetime")
async def test__get_spdx_packages_from_base_images(
    mock_datetime: MagicMock,
    base_images_refs: list[str],
    base_images: dict[str, Image],
    expected_output: tuple[list[Package], list[Annotation]],
) -> None:
    mock_datetime.now.return_value = datetime.datetime(1970, 1, 1)
    assert (
        await _get_spdx_packages_from_base_images(base_images_refs, base_images)
        == expected_output
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["sbom_additional_fields", "base_image_refs", "base_images", "expected_output"],
    [
        (
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-foo",
                        "name": "foo",
                        "downloadLocation": "NOASSERTION",
                    },
                    {
                        "SPDXID": "SPDXRef-bar",
                        "name": "bar",
                        "downloadLocation": "NOASSERTION",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                    {
                        "spdxElementId": "SPDXRef-bar",
                        "relationshipType": "BUILD_TOOL_OF",
                        "relatedSpdxElement": "SPDXRef-foo",
                    },
                ],
            },
            ["alpine:3.10", "foobar:v1"],
            {
                "alpine:3.10": Image.from_image_index_url_and_digest(
                    "alpine:3.10", "sha256:1"
                ),
                "foobar:v1": Image.from_image_index_url_and_digest(
                    "foobar:v1", "sha256:2"
                ),
            },
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
                packages=[
                    Package(
                        spdx_id="SPDXRef-foo",
                        name="foo",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-bar",
                        name="bar",
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-image-alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                        name="alpine",
                        version="3.10",
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION, name="Red Hat"
                        ),
                        files_analyzed=False,
                        checksums=[
                            Checksum(algorithm=ChecksumAlgorithm.SHA256, value="1")
                        ],
                        license_declared=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/alpine@sha256:1?repository_url=alpine",
                            )
                        ],
                        download_location=SpdxNoAssertion(),
                    ),
                    Package(
                        spdx_id="SPDXRef-image-foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e",
                        name="foobar",
                        download_location=SpdxNoAssertion(),
                        version="v1",
                        supplier=Actor(
                            actor_type=ActorType.ORGANIZATION, name="Red Hat"
                        ),
                        files_analyzed=False,
                        checksums=[
                            Checksum(algorithm=ChecksumAlgorithm.SHA256, value="2")
                        ],
                        license_declared=SpdxNoAssertion(),
                        external_references=[
                            ExternalPackageRef(
                                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                                reference_type="purl",
                                locator="pkg:oci/foobar@sha256:2?repository_url=foobar",
                            )
                        ],
                    ),
                ],
                relationships=[
                    Relationship(
                        spdx_element_id="SPDXRef-DOCUMENT",
                        relationship_type=RelationshipType.DESCRIBES,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-bar",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-image-alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                        relationship_type=RelationshipType.BUILD_TOOL_OF,
                        related_spdx_element_id="SPDXRef-foo",
                    ),
                    Relationship(
                        spdx_element_id="SPDXRef-foo",
                        relationship_type=RelationshipType.DESCENDANT_OF,
                        related_spdx_element_id="SPDXRef-image-foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e",
                    ),
                ],
                annotations=[
                    Annotation(
                        spdx_id="SPDXRef-image-alpine-204f767854409b9fcd248f74feb9f61e6e89fe60bb633fa93590c7a397db7fb9",
                        annotation_type=AnnotationType.OTHER,
                        annotator=Actor(
                            actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                        ),
                        annotation_date=datetime.datetime(1970, 1, 1),
                        annotation_comment='{"name":"konflux:container:is_builder_image:for_stage","value":"0"}',
                    ),
                    Annotation(
                        spdx_id="SPDXRef-image-foobar-c1cf745519920203df7cb8ac3b38264ab832e5bcf59bdecf6a2face5d9178e9e",
                        annotation_type=AnnotationType.OTHER,
                        annotator=Actor(
                            actor_type=ActorType.TOOL, name="konflux:jsonencoded"
                        ),
                        annotation_date=datetime.datetime(1970, 1, 1),
                        annotation_comment='{"name":"konflux:container:is_base_image","value":"true"}',
                    ),
                ],
            ),
        ),
        (
            {},
            [],
            {},
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
            ),
        ),
    ],
)
@patch("mobster.cmd.generate.oci_image.base_images_dockerfile.datetime")
async def test__extend_spdx_with_base_images(
    mock_datetime: MagicMock,
    spdx_sbom_skeleton: dict[str, Any],
    sbom_additional_fields: dict[str, Any],
    base_image_refs: list[str | None],
    base_images: dict[str, Image],
    expected_output: Document,
) -> None:
    mock_datetime.now.return_value = datetime.datetime(1970, 1, 1)
    new_sbom = spdx_sbom_skeleton.copy()
    new_sbom.update(sbom_additional_fields)
    sbom_doc_object = JsonLikeDictParser().parse(new_sbom)
    await _extend_spdx_with_base_images(sbom_doc_object, base_image_refs, base_images)
    assert sbom_doc_object == expected_output


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
async def test__extend_cdx_with_base_images(
    input_sbom_dict: dict[str, Any],
    base_image_refs: list[str | None],
    base_images: dict[str, Image],
    expected_sbom: dict[str, Any],
) -> None:
    initial_sbom = CycloneDX1BomWrapper.from_dict(input_sbom_dict)
    await _extend_cdx_with_base_images(initial_sbom, base_image_refs, base_images)
    updated_sbom_dict = initial_sbom.to_dict()
    assert updated_sbom_dict == expected_sbom


@pytest.mark.asyncio
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.get_base_images_refs_from_dockerfile"
)
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.get_objects_for_base_images"
)
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile._extend_cdx_with_base_images"
)
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile._extend_spdx_with_base_images"
)
@pytest.mark.parametrize(
    ["input_sbom_object"],
    [
        (CycloneDX1BomWrapper(sbom=None),),
        (
            Document(
                creation_info=CreationInfo(
                    spdx_version="SPDX-2.3",
                    spdx_id="SPDXRef-DOCUMENT",
                    name="foo",
                    document_namespace="https://foo.example.com/bar",
                    created=datetime.datetime(1970, 1, 1, 0, 0, 0),
                    creators=[Actor(actor_type=ActorType.TOOL, name="Konflux")],
                ),
            ),
        ),
    ],
)
async def test_extend_sbom_with_base_images_from_dockerfile(
    mock__extend_spdx_with_base_images: AsyncMock,
    mock__extend_cdx_with_base_images: AsyncMock,
    mock_get_objects_for_base_images: AsyncMock,
    mock_get_base_images_refs_from_dockerfile: AsyncMock,
    input_sbom_object: CycloneDX1BomWrapper | Document,
) -> None:
    mock_parsed_dockerfile = MagicMock()
    mock_dockerfile_target = MagicMock()
    await extend_sbom_with_base_images_from_dockerfile(
        input_sbom_object, mock_parsed_dockerfile, mock_dockerfile_target
    )
    mock_get_base_images_refs_from_dockerfile.assert_awaited_once_with(
        mock_parsed_dockerfile, mock_dockerfile_target
    )
    mock_get_objects_for_base_images.assert_awaited_once_with(
        mock_get_base_images_refs_from_dockerfile.return_value
    )
    if isinstance(input_sbom_object, CycloneDX1BomWrapper):
        mock__extend_cdx_with_base_images.assert_awaited_once_with(
            input_sbom_object,
            mock_get_base_images_refs_from_dockerfile.return_value,
            mock_get_objects_for_base_images.return_value,
        )
    else:
        mock__extend_spdx_with_base_images.assert_awaited_once_with(
            input_sbom_object,
            mock_get_base_images_refs_from_dockerfile.return_value,
            mock_get_objects_for_base_images.return_value,
        )
