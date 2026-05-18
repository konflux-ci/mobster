from pathlib import Path

import pytest

from tests.integration.img_utils import make_metadata_yaml
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.oci_image.conftest import GenerateData, run_mobster_generate, verify_sbom_relationships
from tests.spdx_builder import AnnotatedPackage


@pytest.mark.asyncio
async def test_builder_content(
        oci_client: ReferrersTagOCIClient,
        tmp_path: Path,
        grandparent_input_sbom: Path,
        parent_input_sbom: Path,
        parent_build_metadata: Path,
        grandparent_packages: list[AnnotatedPackage],
        parent_packages: list[AnnotatedPackage],
    ) -> None:

    # first, set up the parent/grandparent image
    grandparent_img = await oci_client.create_image("grandparent", "latest")
    parent_img = await oci_client.create_image("parent", "latest")

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
        metadata_path=make_metadata_yaml(tmp_path, parent_img, grandparent_img),
        build_metadata_path=parent_build_metadata,
        input_sbom_path=parent_input_sbom,
        output_sbom_path=tmp_path / "parent.output.spdx.json",
        contextualize=True,
    )

    run_mobster_generate(parent_gdata)

    verify_sbom_relationships(parent_gdata.output_sbom_path,
                              [grandparent_packages, parent_packages])
