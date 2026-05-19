from pathlib import Path

import pytest

from tests.integration.img_utils import make_metadata_yaml
from tests.integration.oci_client import ReferrersTagOCIClient
from mobster.cmd.generate.oci_image.contextual_sbom.builder import BuilderPkgMetadata
from tests.integration.oci_image.conftest import (
    GenerateData,
    SBOMPackage,
    run_mobster_generate,
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
    # first, set up the parent/grandparent image
    grandparent_img = await oci_client.create_image("grandparent", "latest")
    parent_img = await oci_client.create_image("parent", "latest")

    parent_build_metadata = BuilderPkgMetadata(
        packages=[
            gin_pkg.to_metadata("builder", grandparent_img.reference),
            # this package provides different data from the SPDX - we're trying
            # to verify that mobster properly attributes packages mentioned in
            # the build data to their calculated origins, so we spoof this
            # package as coming from the grandparent here
            crypto_pkg.to_metadata("builder", grandparent_img.reference),
            random_pkg.to_metadata("intermediate", parent_img.reference),
            malware_pkg.to_metadata("intermediate", parent_img.reference),
            ginkgo_pkg.to_metadata("intermediate", parent_img.reference),
        ]
    )
    parent_build_metadata_path = tmp_path / "parent.buildmetadata.json"
    with open(parent_build_metadata_path, "w") as fp:
        fp.write(parent_build_metadata.model_dump_json())

    # generate the (mobsterized) sbom for the grandparent image
    # (there's no need to contextualize this one, it's functionally built `FROM
    # scratch`)
    grandparent_gdata = GenerateData(
        image=grandparent_img,
        input_sbom_path=grandparent_input_sbom,
        output_sbom_path=tmp_path / "grandparent.output.spdx.json",
    )

    run_mobster_generate(grandparent_gdata)

    # attach the sbom to the image in the oci registry (mobster will pull this later)
    with open(grandparent_gdata.output_sbom_path, "rb") as f:
        await oci_client.attach_sbom(grandparent_img, "spdx", f.read())

    # now generate the (mobsterized) sbom for the parent image
    parent_gdata = GenerateData(
        metadata_path=make_metadata_yaml(tmp_path, parent_img, [grandparent_img], extra_imgs=[grandparent_img]),
        build_metadata_path=parent_build_metadata_path,
        input_sbom_path=parent_input_sbom,
        output_sbom_path=tmp_path / "parent.output.spdx.json",
        contextualize=True,
    )

    run_mobster_generate(parent_gdata)

    verify_sbom_relationships(
        parent_gdata.output_sbom_path, [
            # parent packages
            [
                random_pkg.to_spdx(),
                malware_pkg.to_spdx(),
                ginkgo_pkg.to_spdx(),
            ],
            # grandparent packages
            [gin_pkg.to_spdx(), crypto_pkg.to_spdx()],
        ]
    )
