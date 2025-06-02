import json
import pathlib
import tempfile
from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.oci_artifact import GenerateOciArtifactCommand
from tests.conftest import assert_cdx_sbom, assert_spdx_sbom


@pytest.mark.asyncio
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["sbom_type", "expected_result_file"],
    [
        pytest.param(
            "spdx",
            "oci_artifact_sbom.spdx.json",
            id="SPDX oci artifact",
        ),
        pytest.param(
            "cyclonedx",
            "oci_artifact_sbom.cyclonedx.json",
            id="Cyclonedx oci artifact",
        ),
    ],
)
async def test_GenerateOciArtifactCommand_execute(
    sbom_type: str, expected_result_file: str
) -> None:
    args = MagicMock()
    current_dir = pathlib.Path(__file__).parent.resolve()
    args.oci_copy_yaml = current_dir.parent.parent / "data/oci_copy_example.yaml"
    args.image_pullspec = "quay.io/example/base:v9.0"
    args.image_digest = (
        "sha256:087dc7896b97911a582702b45ff1d41ffa3e142d0b000b0fbb11058188293cfc"
    )
    args.sbom_type = sbom_type

    expected_output_path = current_dir.parent.parent / "data" / expected_result_file
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GenerateOciArtifactCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "oci_artifact.json"
        await command.execute()
        await command.save()

        assert command._content is not None
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

            if sbom_type == "spdx":
                assert_spdx_sbom(result, expected_output)
            if sbom_type == "cyclonedx":
                assert_cdx_sbom(result, expected_output)
