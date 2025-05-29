import json
import pathlib
import tempfile
from typing import Any
from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.modelcar import GenerateModelcarCommand


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["sbom_type", "expected_result_file"],
    [
        pytest.param(
            "spdx",
            "modelcar_sbom.spdx.json",
            id="SPDX modelcar",
        ),
        pytest.param(
            "cyclonedx",
            "modelcar_sbom.cyclonedx.json",
            id="Cyclonedx modelcar",
        ),
    ],
)
async def test_generate_modelcar_sbom(
    sbom_type: str, expected_result_file: str
) -> None:
    """
    This test verifies the generation of an OCI index SBOM end-to-end.
    """

    args = MagicMock()
    current_dir = pathlib.Path(__file__).parent.resolve()
    args.modelcar_image = (
        "quay.io/example/modelcar:v22@sha256:"
        "cc6016b62f25d56507033c48b04517ba40b3490b1e9b01f1c485371311ed42c4"
    )
    args.base_image = (
        "quay.io/example/base:9.0@sha256:"
        "96fbb4c227d543011dfff0679a89ce664d1a009654858f2df28be504bc1863c1"
    )
    args.model_image = (
        "quay.io/example/model:v1@sha256:"
        "087dc7896b97911a582702b45ff1d41ffa3e142d0b000b0fbb11058188293cfc"
    )
    args.sbom_type = sbom_type

    expected_output_path = current_dir.parent.parent / "data" / expected_result_file
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GenerateModelcarCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "modelcar_sbom.json"
        await command.execute()
        await command.save()

        assert command._content is not None
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

            if sbom_type == "spdx":
                # Copy dynamic values from expected output
                result["creationInfo"]["created"] = expected_output["creationInfo"][
                    "created"
                ]
                result["documentNamespace"] = expected_output["documentNamespace"]
            if sbom_type == "cyclonedx":
                result["serialNumber"] = expected_output["serialNumber"]
                result["metadata"]["timestamp"] = expected_output["metadata"][
                    "timestamp"
                ]
                root_bom_ref = result["metadata"]["component"]["bom-ref"]
                patch_bom_ref(
                    result,
                    root_bom_ref,
                    expected_output["metadata"]["component"]["bom-ref"],
                )

            assert result == expected_output


def patch_bom_ref(document: Any, old: str, new: str) -> Any:
    document["metadata"]["component"]["bom-ref"] = new
    for component in document["components"]:
        if component["bom-ref"] == old:
            component["bom-ref"] = new
    for dependency in document["dependencies"]:
        if dependency["ref"] == old:
            dependency["ref"] = new
    return document
