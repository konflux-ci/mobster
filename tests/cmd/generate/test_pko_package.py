import json
import pathlib
import tempfile
from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.pko_package import GeneratePkoPackageCommand
from tests.conftest import assert_cdx_sbom, assert_spdx_sbom


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["sbom_type", "expected_result_file"],
    [
        pytest.param(
            "spdx",
            "pko_package_sbom.spdx.json",
            id="SPDX modelcar",
        ),
        pytest.param(
            "cyclonedx",
            "pko_package_sbom.cyclonedx.json",
            id="Cyclonedx modelcar",
        ),
    ],
)
async def test_generate_pko_package_sbom(
    sbom_type: str, expected_result_file: str
) -> None:
    """
    This test verifies the generation of a pko package SBOM end-to-end.
    """

    digest = "sha256:91601fa0cc411d47d8e777bba7d6e1e0576e226f5b33fb8babcaf6f266bf0fa2"
    ref = "ea2eddf4769f79d799102a0761d6c0a599b4421a"
    path = "config/packages/test-stub"
    url = f"git+https://github.com/package-operator/package-operator.git#ref={ref}&path={path}"

    args = MagicMock()
    current_dir = pathlib.Path(__file__).parent.resolve()
    args.package_pullspec = "quay.io/app-sre/test-stub:5bfd6fb"
    args.package_digest = digest
    args.url = url
    args.sbom_type = sbom_type

    expected_output_path = current_dir.parent.parent / "data" / expected_result_file
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GeneratePkoPackageCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "pko_package_sbom.json"
        await command.execute()
        await command.save()

        assert command._content is not None
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

            if sbom_type == "spdx":
                assert_spdx_sbom(result, expected_output)
            if sbom_type == "cyclonedx":
                assert_cdx_sbom(result, expected_output)
