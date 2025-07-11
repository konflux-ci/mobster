import datetime
import json
from pathlib import Path
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import Package

from mobster.cmd.generate.oci_image import GenerateOciImageCommand
from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from tests.conftest import assert_cdx_sbom


@pytest.fixture()
def image_digest_file_content() -> str:
    return (
        "quay.io/redhat-user-workloads/"
        "rhtap-integration-tenant/konflux-test:"
        "baf5e59d5d35615d0db13b46bd91194458011af8 "
        "quay.io/redhat-user-workloads/rhtap-integration-tenant/"
        "konflux-test:baf5e59d5d35615d0db13b46bd91194458011af8@"
        "sha256:3191d33c484a1cfe5d559200aa75670c41770abf3316244c28eec20a8dba3e0c\n"
        "quay.io/redhat-user-workloads/rhtap-shared-team-tenant/"
        "tssc-test:tssc-test-on-push-2m6dq-build-container "
        "quay.io/redhat-user-workloads/rhtap-shared-team-tenant/"
        "tssc-test:tssc-test-on-push-2m6dq-build-container@"
        "sha256:04f8c3262172fa024beaed2b120414d6011d0c0d4ea578619e32a3c353ec5ee5"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "syft_boms",
        "hermeto_bom",
        "image_pullspec",
        "image_digest",
        "parsed_dockerfile_path",
        "dockerfile_target_stage",
        "use_base_image_digest_content",
        "additional_base_images",
        "contextualize",
        "expected_sbom_path",
    ],
    [
        (
            [Path("tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json")],
            Path("tests/sbom/test_merge_data/spdx/cachi2.bom.json"),
            "quay.io/foobar/examplecontainer:v10",
            "sha256:11111111111111111111111111111111",
            Path("tests/data/dockerfiles/somewhat_believable_sample/parsed.json"),
            "runtime",
            True,
            ["quay.io/ubi9:latest@sha256:123456789012345678901234567789012"],
            True,
            Path("tests/sbom/test_oci_generate_data/generated.spdx.json"),
        ),
        (
            [Path("tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json")],
            None,
            "quay.io/foobar/examplecontainer:v10",
            "sha256:11111111111111111111111111111111",
            Path("tests/data/dockerfiles/somewhat_believable_sample/parsed.json"),
            "builder",
            True,
            [],
            True,
            Path(
                "tests/sbom/test_oci_generate_data/generated_without_hermet_without_additional.spdx.json"
            ),
        ),
        (
            [
                Path(
                    "tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json"
                ),
                Path("tests/sbom/test_merge_data/spdx/syft-sboms/ubi-micro.bom.json"),
            ],
            None,
            "quay.io/foobar/examplecontainer:v10",
            "sha256:11111111111111111111111111111111",
            Path("tests/data/dockerfiles/somewhat_believable_sample/parsed.json"),
            "builder",
            False,
            [],
            True,
            Path("tests/sbom/test_oci_generate_data/generated_multiple_syft.spdx.json"),
        ),
        (
            [
                Path(
                    "tests/sbom/test_merge_data/cyclonedx/syft-sboms/pip-e2e-test.bom.json"
                ),
            ],
            None,
            "quay.io/foobar/examplecontainer:v10",
            "sha256:11111111111111111111111111111111",
            Path("tests/data/dockerfiles/somewhat_believable_sample/parsed.json"),
            "builder",
            True,
            ["quay.io/ubi9:latest@sha256:123456789012345678901234567789012"],
            True,
            Path("tests/sbom/test_oci_generate_data/generated.cdx.json"),
        ),
    ],
)
@patch("mobster.cmd.generate.oci_image.base_images_dockerfile.open")
async def test_GenerateOciImageCommand_execute(
    mock_open_digest_file: MagicMock,
    syft_boms: list[Path],
    hermeto_bom: Path,
    image_pullspec: str,
    image_digest: str,
    parsed_dockerfile_path: Path,
    dockerfile_target_stage: str | None,
    use_base_image_digest_content: bool,
    additional_base_images: list[str],
    contextualize: bool,
    expected_sbom_path: Path,
    image_digest_file_content: str,
) -> None:
    args = MagicMock()
    args.from_syft = syft_boms
    args.from_hermeto = hermeto_bom
    args.image_pullspec = image_pullspec
    args.image_digest = image_digest
    args.parsed_dockerfile_path = parsed_dockerfile_path
    args.dockerfile_target = dockerfile_target_stage
    args.additional_base_image = additional_base_images
    if not use_base_image_digest_content:
        args.base_image_digest_file = None
    else:
        (
            mock_open_digest_file.return_value.__enter__.return_value.readlines
        ).return_value = image_digest_file_content.split("\n")
    command = GenerateOciImageCommand(args)

    with open(expected_sbom_path) as expected_file_stream:
        expected_sbom = json.load(expected_file_stream)

    def compare_spdx_sbom_dicts(
        actual: dict[str, Any], expected: dict[str, Any]
    ) -> None:
        for index, package in enumerate(actual["packages"]):
            for key, value in package.items():
                if key == "annotations":
                    for annotation_idx, annotation in enumerate(value):
                        for annotation_key in (
                            "annotationType",
                            "annotator",
                            "comment",
                            # Ignore annotationDate
                        ):
                            try:
                                assert (
                                    annotation[annotation_key]
                                    == expected["packages"][index]["annotations"][
                                        annotation_idx
                                    ][annotation_key]
                                )
                            except (KeyError, IndexError):
                                raise AssertionError(
                                    f"Cannot match package {package} with the"
                                    f" expected value {expected['packages'][index]}"
                                ) from None
        assert actual["relationships"] == expected["relationships"]

    def compare_sbom_dicts(actual: dict[str, Any], expected: dict[str, Any]) -> None:
        if "spdxVersion" in actual and "spdxVersion" in expected:
            return compare_spdx_sbom_dicts(actual, expected)
        return assert_cdx_sbom(actual, expected)

    sbom = await command.execute()
    sbom_dict = await GenerateOciImageCommand.dump_sbom_to_dict(sbom)

    compare_sbom_dicts(sbom_dict, expected_sbom)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["pullspec", "digest", "oras_response", "expected_action"],
    [
        ("foo:v1", "sha256:1", None, "run"),
        ("foo:v1", None, "sha256:1", "ask-oras"),
        (None, None, None, "nothing"),
        (None, "sha256:1", None, "warning"),
        ("foo:v1", None, None, "error"),
    ],
)
@patch("mobster.cmd.generate.oci_image.LOGGER")
@patch("mobster.cmd.generate.oci_image.json")
@patch("mobster.cmd.generate.oci_image.extend_sbom_with_image_reference")
@patch("mobster.cmd.generate.oci_image.get_digest_for_image_ref")
@patch("mobster.cmd.generate.oci_image.open")
async def test_GenerateOciImageCommand_execute_handle_pullspec(
    mock_open: MagicMock,
    mock_get_digest: AsyncMock,
    mock_extend_sbom: AsyncMock,
    mock_json: MagicMock,
    mock_logger: MagicMock,
    pullspec: str | None,
    digest: str | None,
    oras_response: str | None,
    expected_action: Literal["run", "warning", "error", "nothing", "ask-oras"],
) -> None:
    mock_json.load.return_value = {"spdxVersion": "SPDX-2.3"}
    mock_get_digest.return_value = oras_response

    args = MagicMock()
    args.from_syft = [Path("foo")]
    args.from_hermeto = None
    args.image_pullspec = pullspec
    args.image_digest = digest
    args.parsed_dockerfile_path = None
    args.dockerfile_target = None
    args.additional_base_image = []
    command = GenerateOciImageCommand(args)
    if expected_action == "error":
        with pytest.raises(ValueError):
            await command.execute()
    else:
        await command.execute()
        if expected_action == "nothing":
            mock_extend_sbom.assert_not_awaited()
            return
        if expected_action == "warning":
            mock_logger.warning.assert_any_call(
                "Provided image digest but no pullspec. The digest value is ignored."
            )
            return
        if expected_action == "ask-oras":
            mock_get_digest.assert_awaited_once()

        mock_extend_sbom.assert_awaited_once()


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.open")
@patch("mobster.cmd.generate.oci_image.json")
async def test_GenerateOciImageCommand_execute_unknown_sbom(
    mock_json: MagicMock, mock_open: MagicMock
) -> None:
    args = MagicMock()
    mock_json.load.return_value = {"foo": "bar"}
    args.from_syft = [Path("foo")]
    args.from_hermeto = None
    args.image_pullspec = None
    args.image_digest = None
    args.parsed_dockerfile_path = None
    args.dockerfile_target = None
    args.additional_base_image = []
    command = GenerateOciImageCommand(args)
    with pytest.raises(ValueError):
        await command.execute()


@pytest.mark.asyncio
@pytest.mark.parametrize(["save_file"], [(None,), (Path("foo"),)])
@patch("mobster.cmd.generate.oci_image.open")
@patch("mobster.cmd.generate.oci_image.print")
@patch("mobster.cmd.generate.oci_image.GenerateOciImageCommand.dump_sbom_to_dict")
async def test_GenerateOciImageCommand_save(
    mock_dump_sbom_to_dict: AsyncMock,
    mock_print: MagicMock,
    mock_open: MagicMock,
    save_file: Path | None,
) -> None:
    mock_dump_sbom_to_dict.return_value = {}
    args = MagicMock()
    args.output = save_file
    command = GenerateOciImageCommand(args)
    await command.save()
    mock_dump_sbom_to_dict.assert_awaited_once()
    if save_file:
        mock_open.assert_called_once_with(save_file, "w", encoding="utf-8")
    else:
        mock_print.assert_called_once()


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.LOGGER")
async def test_GenerateOciImageCommand__soft_validate_content_spdx(
    mock_logger: MagicMock,
) -> None:
    command = GenerateOciImageCommand(MagicMock())
    command._content = Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="foo",
            document_namespace="https://foo.bar/example",
            created=datetime.datetime(1970, 1, 1),
            creators=[],
        ),
        packages=[
            Package("a", "b", "c", file_name="/foo.bar"),
            Package("b", "c", "d", file_name="/var/foo.spam"),
        ],
    )
    await command._soft_validate_content()
    mock_logger.warning.assert_called()


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.LOGGER")
async def test_GenerateOciImageCommand__soft_validate_content_cdx(
    mock_logger: MagicMock,
) -> None:
    cdx_sbom_object = Bom(
        components=[
            Component(name="a", type=ComponentType.APPLICATION, bom_ref=BomRef("a"))
        ],
        dependencies=[
            Dependency(ref=BomRef("a"), dependencies=[Dependency(ref=BomRef("b"))])
        ],
    )
    command = GenerateOciImageCommand(MagicMock())
    command._content = CycloneDX1BomWrapper(sbom=cdx_sbom_object)
    await command._soft_validate_content()
    mock_logger.warning.assert_called()
