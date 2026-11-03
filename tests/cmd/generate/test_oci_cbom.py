from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import (
    AnalysisTechnique,
    ComponentEvidence,
    Identity,
    IdentityField,
    Method,
    Occurrence,
)
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoExecutionEnvironment,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.tool import ToolRepository

from mobster.cmd.generate.oci_cbom import GenerateOciCBOMCommand, OciCBOMArgs
from mobster.sbom.cyclonedx_wrapper import CycloneDX1BomWrapper

mock_md5_component = Component(
    name="MD5",
    evidence=ComponentEvidence(
        identity=Identity(
            field=IdentityField.NAME,
            confidence=Decimal(1),
            methods=[
                Method(
                    technique=AnalysisTechnique.SOURCE_CODE_ANALYSIS,
                    confidence=Decimal(1),
                    value="scanoss:ruleid,open-crypto-rules.c.openssl.algorithm.hash.md5.c.openssl.algorithm.hash.md5.constructor",
                )
            ],
        ),
        occurrences=[
            Occurrence(
                location="/bin/malware",
                line=2,
            )
        ],
    ),
    crypto_properties=CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=AlgorithmProperties(
            primitive=CryptoPrimitive.HASH,
            parameter_set_identifier="128",
            execution_environment=CryptoExecutionEnvironment.SOFTWARE_PLAIN_RAM,
        ),
    ),
)

mock_raw_cbom = CycloneDX1BomWrapper(
    sbom=Bom(
        metadata=BomMetaData(
            tools=ToolRepository(
                components=[
                    Component(
                        type=ComponentType.APPLICATION,
                        group="SCANOSS",
                        name="crypto-finder",
                        version="0.6.7",  # Funny number
                    )
                ]
            )
        ),
        components=[mock_md5_component],
    )
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["args", "expected_purl"],
    [
        (
            OciCBOMArgs(
                image_pullspec="quay.io/foo/bar:latest",
                image_digest="sha256:4",  # do not use as a private key
                cbom_path=Path("/tmp/cbom.json"),
                arch=None,
            ),
            "pkg:oci/bar@sha256:4?repository_url=quay.io/foo/bar",
        ),
        (
            OciCBOMArgs(
                image_pullspec="quay.io/fee/bear:earliest",
                image_digest="sha256:42",
                cbom_path=Path("/tmp/cbom.json"),
                arch="amd64",
            ),
            "pkg:oci/bear@sha256:42?arch=amd64&repository_url=quay.io/fee/bear",
        ),
    ],
)
async def test_generate_oci_cbom(args: OciCBOMArgs, expected_purl: str) -> None:
    """
    Tests that the resulting bom has metadata.component with the expected purl.
    """
    cmd = GenerateOciCBOMCommand(cli_args=args)
    with patch("mobster.cmd.generate.oci_cbom.load_file_to_sbom") as mock_load_file:
        mock_load_file.return_value = deepcopy(mock_raw_cbom)
        updated_bom = await cmd.execute()
    assert updated_bom.sbom.metadata.component is not None
    assert updated_bom.sbom.metadata.component.purl is not None
    assert updated_bom.sbom.metadata.component.purl.to_string() == expected_purl
    assert len(updated_bom.sbom.components) == 1
    # comparing the component directly fails because CDX library generates unique
    # BomRef objects for the compared versions
    assert updated_bom.sbom.components[0].name == mock_md5_component.name
    # Check dependencies (CDX library adds dependency object for each component,
    # majority are empty)
    important_dependency: Dependency = next(
        filter(
            lambda x:  # type: ignore[arg-type]
            x.ref == updated_bom.sbom.metadata.component.bom_ref,
            updated_bom.sbom.dependencies,
        )
    )
    assert (
        important_dependency.dependencies[0].ref
        == updated_bom.sbom.components[0].bom_ref
    )
