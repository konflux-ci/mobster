import json
import pathlib
import tempfile
from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate import GenerateOciIndexCommand


@pytest.mark.asyncio
async def test_generate_oci_index_sbom() -> None:
    """
    This test verifies the generation of an OCI index SBOM end-to-end.
    """

    args = MagicMock()
    current_dir = pathlib.Path(__file__).parent.resolve()
    args.index_manifest_path = current_dir.parent / "data/index_manifest.json"
    args.index_image_pullspec = "registry.redhat.io/ubi10-beta/ubi:latest"
    args.index_image_digest = (
        "sha256:4b4976d86eefeedab6884c9d2923206c6c3c2e2471206f97fd9d7aaaecbc04ac"
    )

    expected_output_path = current_dir.parent / "data/index_manifest_sbom.spdx.json"
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GenerateOciIndexCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "index_manifest_sbom.spdx.json"
        await command.execute()
        await command.save()

        assert command._content is not None
        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

            # Copy dynamic values from expected output
            result["creationInfo"]["created"] = expected_output["creationInfo"][
                "created"
            ]
            result["documentNamespace"] = expected_output["documentNamespace"]

            assert result == expected_output
