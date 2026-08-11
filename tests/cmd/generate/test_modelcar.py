import json
import pathlib
import tempfile
from argparse import ArgumentError
from unittest.mock import MagicMock

import pytest

from mobster.cmd.generate.modelcar import (
    GenerateModelcarCommand,
    merge_syft_packages_into_modelcar_spdx,
)
from tests.conftest import assert_cdx_sbom, assert_spdx_sbom


def _modelcar_args(**overrides: object) -> MagicMock:
    args = MagicMock()
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
    args.sbom_type = "spdx"
    args.from_syft = None
    args.skip_validation = True
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


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

    args = _modelcar_args(sbom_type=sbom_type)
    current_dir = pathlib.Path(__file__).parent.resolve()

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
                assert_spdx_sbom(result, expected_output)
            if sbom_type == "cyclonedx":
                assert_cdx_sbom(result, expected_output)


def test_merge_syft_packages_into_modelcar_spdx() -> None:
    modelcar = {
        "packages": [
            {
                "SPDXID": "SPDXRef-root",
                "name": "modelcar",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:oci/modelcar@sha256:aaa",
                    }
                ],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-root",
            }
        ],
    }
    syft = {
        "packages": [
            {
                "SPDXID": "SPDXRef-bash",
                "name": "bash",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:rpm/bash@1.0",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-root",
                "name": "collision",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:rpm/collision@1.0",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-dup",
                "name": "modelcar-dup",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:oci/modelcar@sha256:aaa",
                    }
                ],
            },
        ]
    }

    merged = merge_syft_packages_into_modelcar_spdx(modelcar, [syft])
    package_ids = {pkg["SPDXID"] for pkg in merged["packages"]}
    assert "SPDXRef-bash" in package_ids
    assert "SPDXRef-root-from-syft" in package_ids
    assert "SPDXRef-dup" not in package_ids

    contains = [
        rel for rel in merged["relationships"] if rel["relationshipType"] == "CONTAINS"
    ]
    assert {
        ("SPDXRef-root", "SPDXRef-bash"),
        ("SPDXRef-root", "SPDXRef-root-from-syft"),
    } == {(rel["spdxElementId"], rel["relatedSpdxElement"]) for rel in contains}


@pytest.mark.asyncio
async def test_generate_modelcar_from_syft() -> None:
    current_dir = pathlib.Path(__file__).parent.resolve()
    syft_path = current_dir.parent.parent / "data" / "modelcar_from_syft.spdx.json"
    args = _modelcar_args(from_syft=[syft_path])
    command = GenerateModelcarCommand(args)

    with tempfile.TemporaryDirectory() as temp_dir:
        args.output = pathlib.Path(temp_dir) / "modelcar_sbom.json"
        await command.execute()
        await command.save()

        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

    package_names = {pkg["name"] for pkg in result["packages"]}
    expected_names = {
        "modelcar",
        "base",
        "model",
        "bash",
        "coreutils-single",
        "duplicate-by-id",
    }
    assert expected_names <= package_names

    root_id = next(
        rel["relatedSpdxElement"]
        for rel in result["relationships"]
        if rel["relationshipType"] == "DESCRIBES"
    )
    contains_targets = {
        rel["relatedSpdxElement"]
        for rel in result["relationships"]
        if rel["relationshipType"] == "CONTAINS" and rel["spdxElementId"] == root_id
    }
    assert any("bash" in target for target in contains_targets)
    # SPDX ID collision with modelcar root package is uniquified
    assert any(target.endswith("-from-syft") for target in contains_targets)


@pytest.mark.asyncio
async def test_generate_modelcar_from_syft_rejects_cyclonedx() -> None:
    args = _modelcar_args(
        sbom_type="cyclonedx",
        from_syft=[pathlib.Path("unused.json")],
    )
    command = GenerateModelcarCommand(args)

    with pytest.raises(ArgumentError, match="--from-syft is only supported"):
        await command.execute()
