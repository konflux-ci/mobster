from pathlib import Path

import pytest
from spdx_tools.spdx.parser.parse_anything import parse_file

from tests.integration.img_utils import make_metadata_yaml
from tests.integration.oci_client import ReferrersTagOCIClient
from mobster.cmd.generate.oci_image.contextual_sbom.builder import BuilderPkgMetadata
from mobster.image import Image
from tests.integration.oci_image.conftest import (
    GenerateData,
    SBOMPackage,
    run_mobster_generate,
    verify_relationships,
    verify_sbom_relationships,
)


@pytest.mark.asyncio
async def test_builder_content(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
    grandparent_input_sbom: Path,
    parent_input_sbom: Path,
    gin_pkg: SBOMPackage,
    crypto_pkg: SBOMPackage,
    random_pkg: SBOMPackage,
    malware_pkg: SBOMPackage,
    ginkgo_pkg: SBOMPackage,
) -> None:
    grandparent_img = await oci_client.create_image("grandparent", "latest")
    parent_img = await oci_client.create_image("parent", "latest")

    # mock builder image (this never gets pulled from oci so we don't need to
    # mock it there)
    builder_img = Image(
        repository="localhost:9000/builder",
        digest="sha256:0000000000000000000000000000000000000000000000000000000000000001",
        tag="latest",
    )

    # mock build metadata
    parent_build_metadata = BuilderPkgMetadata(
        packages=[
            # simulates a package COPY'd from the above builder image
            crypto_pkg.to_metadata("builder", builder_img.reference),
        ]
    )
    parent_build_metadata_path = tmp_path / "parent.buildmetadata.json"
    with open(parent_build_metadata_path, "w") as fp:
        fp.write(parent_build_metadata.model_dump_json())

    # generate the grandparent sbom (no contextualization, built FROM scratch)
    grandparent_gdata = GenerateData(
        image=grandparent_img,
        input_sbom_path=grandparent_input_sbom,
        output_sbom_path=tmp_path / "grandparent.output.spdx.json",
    )

    run_mobster_generate(grandparent_gdata)

    with open(grandparent_gdata.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(grandparent_img, "spdx", f.read())

    parent_gdata = GenerateData(
        metadata_path=make_metadata_yaml(
            tmp_path, parent_img, [builder_img, grandparent_img],
        ),
        build_metadata_path=parent_build_metadata_path,
        input_sbom_path=parent_input_sbom,
        output_sbom_path=tmp_path / "parent.output.spdx.json",
        contextualize=True,
    )

    run_mobster_generate(parent_gdata)

    # verify the DESCENDANT_OF chain (parent → grandparent)
    verify_sbom_relationships(
        parent_gdata.output_sbom_path, [
            # parent packages
            [
                random_pkg.to_spdx(),
                malware_pkg.to_spdx(),
                ginkgo_pkg.to_spdx(),
            ],
            # grandparent packages (gin matched via SPDX, crypto stays here
            # from parent contextualization but gets reparented below)
            [gin_pkg.to_spdx()],
        ]
    )

    # verify that the crypto package is marked as actually coming from the
    # builder image
    sbom_doc = parse_file(str(parent_gdata.output_sbom_path))
    verify_relationships(
        builder_img.propose_spdx_id(),
        sbom_doc.relationships,
        [crypto_pkg.to_spdx()],
    )
