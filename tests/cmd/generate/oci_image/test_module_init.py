import datetime
import json
from argparse import ArgumentError
from pathlib import Path
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from _pytest.logging import LogCaptureFixture
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency
from pytest_lazy_fixtures import lf
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import Package

from mobster.cmd.generate.oci_image import GenerateOciImageCommand
from mobster.cmd.enrich import EnrichImageCommand
from mobster.cmd.generate.oci_image.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.image import Image
from tests.conftest import GenerateOciImageTestCase, assert_cdx_sbom, assert_spdx_sbom, EnrichOciImageTestCase


@pytest.fixture()
def image_digest_file_content() -> list[str]:
    return [
        (
            "quay.io/redhat-user-workloads/rhtap-integration-tenant/"
            "konflux-test:baf5e59d5d35615d0db13b46bd91194458011af8 "
            "quay.io/redhat-user-workloads/rhtap-integration-tenant/"
            "konflux-test:baf5e59d5d35615d0db13b46bd91194458011af8@"
            "sha256:3191d33c484a1cfe5d559200aa75670c41770abf3316244c28eec20a8dba3e0c"
        ),
        (
            "quay.io/redhat-user-workloads/rhtap-shared-team-tenant/"
            "tssc-test:tssc-test-on-push-2m6dq-build-container "
            "quay.io/redhat-user-workloads/rhtap-shared-team-tenant/"
            "tssc-test:tssc-test-on-push-2m6dq-build-container@"
            "sha256:04f8c3262172fa024beaed2b120414d6011d0c0d4ea578619e32a3c353ec5ee5"
        ),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_case",
    [
        lf("test_case_spdx_with_hermeto_and_additional"),
        lf("test_case_spdx_without_hermeto_without_additional"),
        lf("test_case_spdx_multiple_syft"),
        lf("test_case_cyclonedx_with_additional"),
    ],
)
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.get_base_images_digests_lines"
)
async def test_GenerateOciImageCommand_execute(
    mock_get_base_images_digests_lines: MagicMock,
    test_case: GenerateOciImageTestCase,
    image_digest_file_content: str,
) -> None:
    # Set up mock for base image digest content if base_image_digest_file is present
    if test_case.args.base_image_digest_file is not None:
        mock_get_base_images_digests_lines.return_value = image_digest_file_content

    command = GenerateOciImageCommand(test_case.args)

    with open(test_case.expected_sbom_path) as expected_file_stream:
        expected_sbom = json.load(expected_file_stream)

    def compare_sbom_dicts(actual: dict[str, Any], expected: dict[str, Any]) -> None:
        if "spdxVersion" in actual and "spdxVersion" in expected:
            return assert_spdx_sbom(actual, expected)
        return assert_cdx_sbom(actual, expected)

    sbom = await command.execute()
    sbom_dict = await GenerateOciImageCommand.dump_sbom_to_dict(sbom)

    compare_sbom_dicts(sbom_dict, expected_sbom)

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_case",
    [
        lf("test_case_enrich_spdx_with_owasp"), 
    ],
)
@patch(
    "mobster.cmd.enrich"
)
async def test_EnrichOciImageCommand_execute(
    mock_enrich,
    test_case: EnrichOciImageTestCase, # pylint: disable=unused-argument
) -> None:

    command = EnrichImageCommand(test_case.args)

    sbom = await command.execute()

    #TODO: finish test case


@pytest.mark.asyncio
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.get_base_images_digests_lines"
)
async def test_GenerateOciImageCommand_execute_cannot_contextualize_cyclonedx(
    image_digest_file_content: str,
    test_case_cyclonedx_with_additional: GenerateOciImageTestCase,
) -> None:
    test_case_cyclonedx_with_additional.args.contextualize = True
    command = GenerateOciImageCommand(test_case_cyclonedx_with_additional.args)
    with pytest.raises(
        ArgumentError,
        match="--contextualize is only allowed when processing SPDX format",
    ):
        await command.execute()


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.get_base_images_refs_from_dockerfile")
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.get_objects_for_base_images"
)
@patch(
    "mobster.cmd.generate.oci_image.base_images_dockerfile.get_base_images_digests_lines"
)
async def test_test_GenerateOciImageCommand_execute_missing_digest(
    mock_get_lines: MagicMock,
    mock_get_images: AsyncMock,
    mock_get_refs: AsyncMock,
    caplog: LogCaptureFixture,
) -> None:
    args = MagicMock(
        parsed_dockerfile_path="tests/data/dockerfiles/sample1/parsed.json",
        base_image_digest_file="bar",
        from_syft=[
            Path("tests/sbom/test_merge_data/spdx/syft-sboms/pip-e2e-test.bom.json")
        ],
        from_hermeto=None,
        image_pullspec=None,
        image_digest=None,
        additional_base_images=[],
    )
    mock_get_refs.return_value = ["foo", "bar"]
    mock_get_images.return_value = {
        "foo": Image.from_image_index_url_and_digest(
            "foo.bar/foo/ham:v1", "sha256:a", "amd64"
        )
    }
    command = GenerateOciImageCommand(args)
    await command.execute()
    assert (
        "Cannot get information about base image bar "
        "mentioned in the Dockerfile! THIS MEANS THE "
        "PRODUCED SBOM WILL BE INCOMPLETE!" in caplog.messages
    )


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
@patch("mobster.cmd.generate.oci_image.extend_sbom_with_image_reference")
@patch("mobster.cmd.generate.oci_image.get_digest_for_image_ref")
@patch("mobster.cmd.generate.oci_image.load_sbom_from_json")
async def test_GenerateOciImageCommand_execute_handle_pullspec(
    mock_load_sbom: AsyncMock,
    mock_get_digest: AsyncMock,
    mock_extend_sbom: AsyncMock,
    mock_logger: MagicMock,
    pullspec: str | None,
    digest: str | None,
    oras_response: str | None,
    expected_action: Literal["run", "warning", "error", "nothing", "ask-oras"],
) -> None:
    mock_load_sbom.return_value = {"spdxVersion": "SPDX-2.3"}
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
@patch("mobster.cmd.generate.oci_image.load_sbom_from_json")
async def test_GenerateOciImageCommand_execute_unknown_sbom(
    mock_load_sbom: AsyncMock,
) -> None:
    args = MagicMock()
    mock_load_sbom.return_value = {"foo": "bar"}
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["syft_boms", "hermeto_bom", "image_pullspec", "expected_action"],
    [
        # no SBOMs
        (None, None, None, "raise_error"),
        # single syft
        ([Path("syft.json")], None, None, "load_syft"),
        # multiple syft
        ([Path("syft1.json"), Path("syft2.json")], None, None, "merge"),
        # syft + hermeto
        ([Path("syft.json")], Path("hermeto.json"), None, "merge"),
        # multiple syft + hermeto
        ([Path("syft1.json"), Path("syft2.json")], Path("hermeto.json"), None, "merge"),
        # only hermeto
        (None, Path("hermeto.json"), None, "load_hermeto"),
        (None, None, "foo:latest", "scan_syft"),
    ],
)
@patch("mobster.cmd.generate.oci_image.syft.scan_image")
@patch("mobster.cmd.generate.oci_image.load_sbom_from_json")
@patch("mobster.cmd.generate.oci_image.merge_sboms")
async def test_GenerateOciImageCommand__handle_bom_inputs(
    mock_merge: MagicMock,
    mock_load_sbom: AsyncMock,
    mock_syft_scan: AsyncMock,
    syft_boms: list[Path],
    hermeto_bom: Path | None,
    image_pullspec: str | None,
    expected_action: Literal["raise_error", "load_syft", "load_hermeto", "merge"],
) -> None:
    command = GenerateOciImageCommand(MagicMock())
    command.cli_args.from_hermeto = hermeto_bom
    command.cli_args.from_syft = syft_boms
    command.cli_args.image_pullspec = image_pullspec

    mock_syft_data = {"name": "syft_data"}
    mock_hermeto_data = {"name": "hermeto_data"}
    mock_merged_data = {"name": "merged_data"}

    mock_load_sbom.side_effect = lambda _: (
        mock_syft_data if hermeto_bom is None else mock_hermeto_data
    )
    mock_merge.return_value = mock_merged_data

    if expected_action == "raise_error":
        with pytest.raises(ArgumentError):
            await command._handle_bom_inputs()
    else:
        result = await command._handle_bom_inputs()

        if expected_action == "load_syft":
            assert syft_boms is not None
            assert hermeto_bom is None
            mock_load_sbom.assert_awaited_once()
            assert result == mock_syft_data
            mock_merge.assert_not_called()

        elif expected_action == "load_hermeto":
            assert hermeto_bom is not None
            assert syft_boms is None
            mock_load_sbom.assert_awaited_once()
            assert result == mock_hermeto_data
            mock_merge.assert_not_called()

        elif expected_action == "merge":
            mock_merge.assert_called_once_with(syft_boms, hermeto_bom)
            assert result == mock_merged_data
            mock_load_sbom.assert_not_awaited()

        elif expected_action == "scan_syft":
            mock_syft_scan.assert_awaited_once_with(image_pullspec)
            mock_load_sbom.assert_not_awaited()
            mock_merge.assert_not_called()


@pytest.mark.asyncio
@patch("mobster.cmd.generate.oci_image.download_parent_image_sbom")
async def test_GenerateOciImageCommand__execute_contextual_workflow_no_downloaded_sbom(
    mock_download_sbom: AsyncMock,
) -> None:
    mock_download_sbom.return_value = None
    command = GenerateOciImageCommand(MagicMock(from_hermeto=None))
    assert (
        await command._execute_contextual_workflow(
            MagicMock(), Image("foo", "sha256:1"), "bar"
        )
        is None
    )


@pytest.mark.asyncio
@patch(
    "mobster.cmd.generate.oci_image.GenerateOciImageCommand._execute_contextual_workflow"
)
async def test_GenerateOciImageCommand__assess_and_dispatch_contextual_workflow(
    mock_execute_contextual: AsyncMock,
) -> None:
    command = GenerateOciImageCommand(MagicMock())
    command.cli_args.contextualize = True
    await command._assess_and_dispatch_contextual_workflow(
        MagicMock(spec=Document),
        ["foo:latest"],
        {"foo:latest": Image("foo:latest", "sha256:1")},
        "amd64",
    )
    mock_execute_contextual.assert_awaited_once()


@pytest.mark.asyncio
@patch(
    "mobster.cmd.generate.oci_image.GenerateOciImageCommand._execute_contextual_workflow"
)
async def test_GenerateOciImageCommand__assess_and_dispatch_contextual_workflow_fail(
    mock_execute_contextual: AsyncMock, caplog: LogCaptureFixture
) -> None:
    command = GenerateOciImageCommand(MagicMock())
    command.cli_args.contextualize = True
    mock_execute_contextual.side_effect = ValueError("error")
    await command._assess_and_dispatch_contextual_workflow(
        MagicMock(spec=Document),
        ["foo:latest"],
        {"foo:latest": Image("foo:latest", "sha256:1")},
        "amd64",
    )
    mock_execute_contextual.assert_awaited_once()
    assert "Contextual SBOM workflow failed." in caplog.messages
