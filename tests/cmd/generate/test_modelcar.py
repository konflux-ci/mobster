import json
import pathlib
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mobster.cmd.generate.modelcar import (
    GenerateModelcarCommand,
    merge_syft_components_into_modelcar_cdx,
    merge_syft_packages_into_modelcar_spdx,
)
from tests.conftest import assert_cdx_sbom, assert_spdx_sbom

BASE_SPDX_ID = (
    "SPDXRef-image-base-94ca2083f75d4e8d47afb9c3e61d2674e57bac4b09d9c4b9fa1df75bb0c8ecef"
)
BASE_CDX_REF = (
    "BomRef.base-94ca2083f75d4e8d47afb9c3e61d2674e57bac4b09d9c4b9fa1df75bb0c8ecef"
)


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
    """Composition SBOM only; Syft inventory merge is skipped via mock."""

    args = _modelcar_args(sbom_type=sbom_type)
    current_dir = pathlib.Path(__file__).parent.resolve()

    expected_output_path = current_dir.parent.parent / "data" / expected_result_file
    with open(expected_output_path, encoding="utf8") as expected_file:
        expected_output = json.load(expected_file)

    command = GenerateModelcarCommand(args)

    with (
        tempfile.TemporaryDirectory() as temp_dir,
        patch.object(
            command,
            "_merge_base_syft_inventory",
            new_callable=AsyncMock,
            side_effect=lambda sbom, _base: sbom,
        ),
    ):
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
            },
            {
                "SPDXID": BASE_SPDX_ID,
                "name": "base",
                "externalRefs": [],
            },
        ],
        "relationships": [],
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
                "SPDXID": BASE_SPDX_ID,
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

    merged = merge_syft_packages_into_modelcar_spdx(modelcar, syft, parent_id=BASE_SPDX_ID)
    package_ids = {pkg["SPDXID"] for pkg in merged["packages"]}
    assert "SPDXRef-bash" in package_ids
    assert f"{BASE_SPDX_ID}-from-syft" in package_ids
    assert "SPDXRef-dup" not in package_ids

    contains = [
        rel for rel in merged["relationships"] if rel["relationshipType"] == "CONTAINS"
    ]
    assert {
        (BASE_SPDX_ID, "SPDXRef-bash"),
        (BASE_SPDX_ID, f"{BASE_SPDX_ID}-from-syft"),
    } == {(rel["spdxElementId"], rel["relatedSpdxElement"]) for rel in contains}


def test_merge_syft_packages_double_spdx_id_collision() -> None:
    """Renamed -from-syft ID must itself be uniquified if already taken."""
    modelcar = {
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "modelcar", "externalRefs": []},
            {"SPDXID": BASE_SPDX_ID, "name": "base", "externalRefs": []},
            {
                "SPDXID": f"{BASE_SPDX_ID}-from-syft",
                "name": "already-renamed",
                "externalRefs": [],
            },
        ],
        "relationships": [],
    }
    syft_sbom = {
        "packages": [
            {
                "SPDXID": BASE_SPDX_ID,
                "name": "collision",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:rpm/collision@1.0",
                    }
                ],
            }
        ]
    }

    merged = merge_syft_packages_into_modelcar_spdx(
        modelcar, syft_sbom, parent_id=BASE_SPDX_ID
    )
    package_ids = {pkg["SPDXID"] for pkg in merged["packages"]}
    assert f"{BASE_SPDX_ID}-from-syft-1" in package_ids
    assert len(package_ids) == len(merged["packages"])

    contains = [
        rel for rel in merged["relationships"] if rel["relationshipType"] == "CONTAINS"
    ]
    assert contains == [
        {
            "spdxElementId": BASE_SPDX_ID,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": f"{BASE_SPDX_ID}-from-syft-1",
        }
    ]


def test_merge_syft_packages_skips_missing_spdxid_and_purl(
    caplog: pytest.LogCaptureFixture,
) -> None:
    modelcar: dict[str, object] = {"packages": [], "relationships": []}
    syft_sbom = {
        "packages": [
            {"name": "no-id", "externalRefs": []},
            {
                "SPDXID": "SPDXRef-nopurl",
                "name": "no-purl",
                "externalRefs": [],
            },
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
        ]
    }

    with caplog.at_level("WARNING"):
        merged = merge_syft_packages_into_modelcar_spdx(
            modelcar, syft_sbom, parent_id=BASE_SPDX_ID
        )

    assert "without SPDXID" in caplog.text
    assert "no purl for deduplication" in caplog.text
    assert {pkg["SPDXID"] for pkg in merged["packages"]} == {"SPDXRef-bash"}


def test_merge_syft_components_into_modelcar_cdx() -> None:
    modelcar = {
        "components": [
            {"bom-ref": "root", "name": "modelcar", "purl": "pkg:oci/modelcar@1"},
            {"bom-ref": BASE_CDX_REF, "name": "base", "purl": "pkg:oci/base@1"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": [BASE_CDX_REF]},
            {"ref": BASE_CDX_REF},
        ],
        "metadata": {"component": {"bom-ref": "root"}},
    }
    syft = {
        "components": [
            {
                "bom-ref": "pkg:rpm/bash@1.0",
                "name": "bash",
                "purl": "pkg:rpm/bash@1.0",
            },
            {
                "bom-ref": BASE_CDX_REF,
                "name": "collision",
                "purl": "pkg:rpm/collision@1.0",
            },
            {
                "bom-ref": "dup",
                "name": "dup",
                "purl": "pkg:oci/modelcar@1",
            },
        ]
    }

    merged = merge_syft_components_into_modelcar_cdx(
        modelcar, syft, parent_ref=BASE_CDX_REF
    )
    refs = {c["bom-ref"] for c in merged["components"]}
    assert "pkg:rpm/bash@1.0" in refs
    assert f"{BASE_CDX_REF}-from-syft" in refs
    assert "dup" not in refs

    base_dep = next(d for d in merged["dependencies"] if d["ref"] == BASE_CDX_REF)
    assert "pkg:rpm/bash@1.0" in base_dep["dependsOn"]
    assert f"{BASE_CDX_REF}-from-syft" in base_dep["dependsOn"]


@pytest.mark.asyncio
async def test_generate_modelcar_scans_base_spdx() -> None:
    current_dir = pathlib.Path(__file__).parent.resolve()
    syft_path = current_dir.parent.parent / "data" / "modelcar_from_syft.spdx.json"
    with open(syft_path, encoding="utf8") as syft_file:
        syft_sbom = json.load(syft_file)

    args = _modelcar_args(sbom_type="spdx")
    command = GenerateModelcarCommand(args)

    with (
        tempfile.TemporaryDirectory() as temp_dir,
        patch(
            "mobster.cmd.generate.modelcar.syft.scan_image",
            new_callable=AsyncMock,
            return_value=syft_sbom,
        ) as mock_scan,
    ):
        args.output = pathlib.Path(temp_dir) / "modelcar_sbom.json"
        await command.execute()
        await command.save()

        mock_scan.assert_awaited_once()
        assert "quay.io/example/base@sha256:" in mock_scan.await_args.args[0]

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

    contains_targets = {
        rel["relatedSpdxElement"]
        for rel in result["relationships"]
        if rel["relationshipType"] == "CONTAINS" and rel["spdxElementId"] == BASE_SPDX_ID
    }
    assert any("bash" in target for target in contains_targets)
    assert any(target.endswith("-from-syft") for target in contains_targets)


@pytest.mark.asyncio
async def test_generate_modelcar_scans_base_cyclonedx() -> None:
    syft_sbom = {
        "components": [
            {
                "bom-ref": "pkg:rpm/bash@1.0",
                "name": "bash",
                "purl": "pkg:rpm/bash@1.0",
                "type": "library",
            }
        ]
    }
    args = _modelcar_args(sbom_type="cyclonedx")
    command = GenerateModelcarCommand(args)

    with (
        tempfile.TemporaryDirectory() as temp_dir,
        patch(
            "mobster.cmd.generate.modelcar.syft.scan_image",
            new_callable=AsyncMock,
            return_value=syft_sbom,
        ) as mock_scan,
    ):
        args.output = pathlib.Path(temp_dir) / "modelcar_sbom.json"
        await command.execute()
        await command.save()

        mock_scan.assert_awaited_once()
        assert mock_scan.await_args.kwargs["output_format"] == "cyclonedx-json"

        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

    names = {c["name"] for c in result["components"]}
    assert "bash" in names
    base_dep = next(d for d in result["dependencies"] if d["ref"] == BASE_CDX_REF)
    assert "pkg:rpm/bash@1.0" in base_dep["dependsOn"]


@pytest.mark.asyncio
async def test_merge_base_syft_rejects_wrong_type() -> None:
    args = _modelcar_args(sbom_type="spdx")
    command = GenerateModelcarCommand(args)
    base = MagicMock()
    base.propose_spdx_id.return_value = BASE_SPDX_ID
    base.reference = "quay.io/example/base@sha256:abc"

    with pytest.raises(TypeError, match="Expected SPDX Document"):
        await command._merge_base_syft_inventory(object(), base)
