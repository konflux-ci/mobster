import json
import pathlib
import tempfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency
from packageurl import PackageURL
from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.extracted_licensing_info import ExtractedLicensingInfo
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

from mobster.cmd.generate.modelcar import (
    GenerateModelcarCommand,
    merge_syft_components_into_modelcar_cdx,
    merge_syft_packages_into_modelcar_spdx,
)
from tests.conftest import assert_cdx_sbom, assert_spdx_sbom

BASE_SPDX_ID = (
    "SPDXRef-image-base-"
    "94ca2083f75d4e8d47afb9c3e61d2674e57bac4b09d9c4b9fa1df75bb0c8ecef"
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


def _spdx_pkg(spdx_id: str, name: str, *purls: str) -> Package:
    refs = [
        ExternalPackageRef(
            category=ExternalPackageRefCategory.PACKAGE_MANAGER,
            reference_type="purl",
            locator=purl,
        )
        for purl in purls
    ]
    return Package(
        name=name,
        spdx_id=spdx_id,
        download_location=SpdxNoAssertion(),
        external_references=refs,
    )


def _spdx_doc(*packages: Package) -> Document:
    return Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test",
            data_license="CC0-1.0",
            document_namespace="https://example.com/test",
            creators=[Actor(ActorType.TOOL, "test")],
            created=datetime(2025, 1, 1, tzinfo=timezone.utc),
        ),
        packages=list(packages),
        relationships=[],
    )


def _cdx_component(bom_ref: str, name: str, purl: str | None = None) -> Component:
    return Component(
        type=ComponentType.LIBRARY,
        name=name,
        bom_ref=BomRef(bom_ref),
        purl=PackageURL.from_string(purl) if purl else None,
    )


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
    modelcar = _spdx_doc(
        _spdx_pkg("SPDXRef-root", "modelcar", "pkg:oci/modelcar@sha256:aaa"),
        _spdx_pkg(BASE_SPDX_ID, "base"),
    )
    syft = _spdx_doc(
        _spdx_pkg("SPDXRef-bash", "bash", "pkg:rpm/bash@1.0"),
        _spdx_pkg(BASE_SPDX_ID, "collision", "pkg:rpm/collision@1.0"),
        _spdx_pkg("SPDXRef-dup", "modelcar-dup", "pkg:oci/modelcar@sha256:aaa"),
    )

    merged = merge_syft_packages_into_modelcar_spdx(
        modelcar, syft, parent_id=BASE_SPDX_ID
    )
    package_ids = {pkg.spdx_id for pkg in merged.packages}
    assert "SPDXRef-bash" in package_ids
    assert f"{BASE_SPDX_ID}-from-syft" in package_ids
    assert "SPDXRef-dup" not in package_ids

    contains = [
        rel
        for rel in merged.relationships
        if rel.relationship_type == RelationshipType.CONTAINS
    ]
    assert {
        (BASE_SPDX_ID, "SPDXRef-bash"),
        (BASE_SPDX_ID, f"{BASE_SPDX_ID}-from-syft"),
    } == {(rel.spdx_element_id, rel.related_spdx_element_id) for rel in contains}


def test_merge_syft_packages_copies_extracted_licensing_info() -> None:
    """LicenseRef-* on Syft packages require hasExtractedLicensingInfos after merge."""
    modelcar = _spdx_doc(_spdx_pkg(BASE_SPDX_ID, "base"))
    syft_pkg = _spdx_pkg("SPDXRef-bash", "bash", "pkg:rpm/bash@1.0")
    syft_pkg.license_declared = spdx_licensing.parse("LicenseRef-GPLv2")
    syft = _spdx_doc(syft_pkg)
    syft.extracted_licensing_info = [
        ExtractedLicensingInfo(
            license_id="LicenseRef-GPLv2",
            extracted_text="GPL-2.0",
            license_name="GPLv2",
        )
    ]

    merged = merge_syft_packages_into_modelcar_spdx(
        modelcar, syft, parent_id=BASE_SPDX_ID
    )
    assert {info.license_id for info in merged.extracted_licensing_info or []} == {
        "LicenseRef-GPLv2"
    }
    license_msgs = [
        msg
        for msg in validate_full_spdx_document(merged)
        if "Unrecognized license reference" in msg.validation_message
    ]
    assert license_msgs == []


def test_merge_syft_packages_double_spdx_id_collision() -> None:
    """Renamed -from-syft ID must itself be uniquified if already taken."""
    modelcar = _spdx_doc(
        _spdx_pkg("SPDXRef-root", "modelcar"),
        _spdx_pkg(BASE_SPDX_ID, "base"),
        _spdx_pkg(f"{BASE_SPDX_ID}-from-syft", "already-renamed"),
    )
    syft = _spdx_doc(_spdx_pkg(BASE_SPDX_ID, "collision", "pkg:rpm/collision@1.0"))

    merged = merge_syft_packages_into_modelcar_spdx(
        modelcar, syft, parent_id=BASE_SPDX_ID
    )
    package_ids = {pkg.spdx_id for pkg in merged.packages}
    assert f"{BASE_SPDX_ID}-from-syft-1" in package_ids

    contains = [
        rel
        for rel in merged.relationships
        if rel.relationship_type == RelationshipType.CONTAINS
    ]
    assert len(contains) == 1
    assert contains[0].related_spdx_element_id == f"{BASE_SPDX_ID}-from-syft-1"


def test_merge_syft_packages_skips_missing_purl(
    caplog: pytest.LogCaptureFixture,
) -> None:
    modelcar = _spdx_doc()
    syft = _spdx_doc(
        _spdx_pkg("SPDXRef-nopurl", "no-purl"),
        _spdx_pkg("SPDXRef-bash", "bash", "pkg:rpm/bash@1.0"),
    )

    with caplog.at_level("WARNING"):
        merged = merge_syft_packages_into_modelcar_spdx(
            modelcar, syft, parent_id=BASE_SPDX_ID
        )

    assert "no purl for deduplication" in caplog.text
    assert {pkg.spdx_id for pkg in merged.packages} == {"SPDXRef-bash"}


def test_merge_syft_packages_purl_dedupe_cases() -> None:
    modelcar = _spdx_doc(_spdx_pkg("SPDXRef-existing", "bash", "pkg:rpm/bash@1.0"))
    syft = _spdx_doc(
        _spdx_pkg("SPDXRef-same-purl", "bash-again", "pkg:rpm/bash@1.0"),
        _spdx_pkg(
            "SPDXRef-multi-purl",
            "multi",
            "pkg:rpm/bash@1.0",
            "pkg:generic/other@1.0",
        ),
        _spdx_pkg("SPDXRef-same-name-diff-purl", "bash", "pkg:rpm/bash@2.0"),
        _spdx_pkg("SPDXRef-new", "coreutils", "pkg:rpm/coreutils@1.0"),
    )

    merged = merge_syft_packages_into_modelcar_spdx(
        modelcar, syft, parent_id=BASE_SPDX_ID
    )
    package_ids = {pkg.spdx_id for pkg in merged.packages}
    assert "SPDXRef-same-purl" not in package_ids
    assert "SPDXRef-multi-purl" not in package_ids
    assert "SPDXRef-same-name-diff-purl" in package_ids
    assert "SPDXRef-new" in package_ids


def test_merge_syft_components_into_modelcar_cdx() -> None:
    root = _cdx_component("root", "modelcar", "pkg:oci/modelcar@1")
    base = _cdx_component(BASE_CDX_REF, "base", "pkg:oci/base@1")
    modelcar = Bom(components=[root, base])
    modelcar.metadata.component = root
    modelcar.dependencies.add(
        Dependency(
            ref=BomRef("root"), dependencies=[Dependency(ref=BomRef(BASE_CDX_REF))]
        )
    )
    modelcar.dependencies.add(Dependency(ref=BomRef(BASE_CDX_REF)))

    syft = Bom(
        components=[
            _cdx_component("pkg:rpm/bash@1.0", "bash", "pkg:rpm/bash@1.0"),
            _cdx_component(BASE_CDX_REF, "collision", "pkg:rpm/collision@1.0"),
            _cdx_component("dup", "dup", "pkg:oci/modelcar@1"),
        ]
    )

    merged = merge_syft_components_into_modelcar_cdx(
        modelcar, syft, parent_ref=BASE_CDX_REF
    )
    refs = {str(c.bom_ref) for c in merged.components}
    assert "pkg:rpm/bash@1.0" in refs
    assert f"{BASE_CDX_REF}-from-syft" in refs
    assert "dup" not in refs

    base_dep = next(d for d in merged.dependencies if str(d.ref) == BASE_CDX_REF)
    depends_on = {str(d.ref) for d in base_dep.dependencies}
    assert "pkg:rpm/bash@1.0" in depends_on
    assert f"{BASE_CDX_REF}-from-syft" in depends_on


def test_merge_syft_components_dedupes_metadata_purl() -> None:
    root = _cdx_component("root", "modelcar", "pkg:oci/modelcar@1")
    modelcar = Bom(components=[])
    modelcar.metadata.component = root
    syft = Bom(
        components=[
            _cdx_component("dup-root", "modelcar-dup", "pkg:oci/modelcar@1"),
            _cdx_component("pkg:rpm/bash@1.0", "bash", "pkg:rpm/bash@1.0"),
        ]
    )

    merged = merge_syft_components_into_modelcar_cdx(
        modelcar, syft, parent_ref=BASE_CDX_REF
    )
    refs = {str(c.bom_ref) for c in merged.components}
    assert "dup-root" not in refs
    assert "pkg:rpm/bash@1.0" in refs


def test_merge_syft_components_skips_missing_purl(
    caplog: pytest.LogCaptureFixture,
) -> None:
    modelcar = Bom(components=[])
    syft = Bom(components=[_cdx_component("no-purl", "nopurl")])

    with caplog.at_level("WARNING"):
        merged = merge_syft_components_into_modelcar_cdx(
            modelcar, syft, parent_ref=BASE_CDX_REF
        )

    assert "no purl for deduplication" in caplog.text
    assert list(merged.components) == []


def test_merge_syft_components_creates_parent_dependency() -> None:
    modelcar = Bom(components=[])
    syft = Bom(
        components=[_cdx_component("pkg:rpm/bash@1.0", "bash", "pkg:rpm/bash@1.0")]
    )

    merged = merge_syft_components_into_modelcar_cdx(
        modelcar, syft, parent_ref=BASE_CDX_REF
    )
    base_dep = next(d for d in merged.dependencies if str(d.ref) == BASE_CDX_REF)
    assert {str(d.ref) for d in base_dep.dependencies} == {"pkg:rpm/bash@1.0"}


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
        scan_call = mock_scan.await_args
        assert scan_call is not None
        assert "quay.io/example/base@sha256:" in scan_call.args[0]

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
        if (
            rel["relationshipType"] == "CONTAINS"
            and rel["spdxElementId"] == BASE_SPDX_ID
        )
    }
    assert any("bash" in target for target in contains_targets)
    assert any(target.endswith("-from-syft") for target in contains_targets)


@pytest.mark.asyncio
async def test_generate_modelcar_scans_base_cyclonedx() -> None:
    syft_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg:rpm/bash@1.0",
                "name": "bash",
                "purl": "pkg:rpm/bash@1.0",
                "type": "library",
            }
        ],
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
        scan_call = mock_scan.await_args
        assert scan_call is not None
        assert scan_call.kwargs["output_format"] == "cyclonedx-json"

        with open(args.output, encoding="utf8") as result_file:
            result = json.load(result_file)

    names = {c["name"] for c in result["components"]}
    assert "bash" in names
    base_dep = next(d for d in result["dependencies"] if d["ref"] == BASE_CDX_REF)
    assert "pkg:rpm/bash@1.0" in base_dep["dependsOn"]


@pytest.mark.asyncio
async def test_merge_base_syft_rejects_wrong_type() -> None:
    args = _modelcar_args()
    command = GenerateModelcarCommand(args)
    base = MagicMock()
    base.reference = "quay.io/example/base@sha256:abc"

    with pytest.raises(TypeError, match="Expected CycloneDX Bom or SPDX Document"):
        await command._merge_base_syft_inventory(object(), base)
