from pathlib import Path
from typing import Any

import pytest
from spdx_tools.spdx.parser.parse_anything import parse_file

from mobster.image import Image
from mobster.sbom import spdx
from tests.integration.oci_client import ReferrersTagOCIClient
from tests.integration.oci_image.conftest import (
    GenerateData,
    run_mobster_generate,
)


def verify_main_oci_package(sbom_doc: Any, image: Image) -> None:
    expected_package = spdx.get_image_package(image, image.propose_spdx_id())

    for pkg in sbom_doc.packages:
        if pkg.name == expected_package.name:
            assert pkg == expected_package
            return
    raise AssertionError(
        "Main OCI image package not found in SBOM. "
        f"Expected package: {expected_package}"
    )


@pytest.mark.asyncio
async def test_generate_oci_image_syft_scan(
    oci_client: ReferrersTagOCIClient,
    tmp_path: Path,
) -> None:
    image = await oci_client.create_image("syft-scan-image", "1.2.3.amd64")
    image.arch = "amd64"
    # Also create index image to verify the scanner picks the right architecture
    await oci_client.create_image_index("syft-scan-image", "1.2.3", images=[image])

    # Remove the digest to force mobster to calculate it again
    image_digest = image.digest
    image.digest = None  # type: ignore[assignment]

    output_sbom_path = tmp_path / "output.spdx.json"

    gdata = GenerateData(
        image=image,
        output_sbom_path=output_sbom_path,
    )

    run_mobster_generate(gdata)

    sbom_doc = parse_file(str(gdata.output_sbom_path))

    # Revert the image digest back for verification
    image.digest = image_digest
    verify_main_oci_package(sbom_doc, image)

    # Verify that the SBOM contains expected packages from the Syft scan
    expected_packages = {
        # In the test image we copy kubebuilder binary
        "sigs.k8s.io/kubebuilder/v3",
    }

    sbom_package_names = {pkg.name for pkg in sbom_doc.packages}

    for expected_package in expected_packages:
        assert expected_package in sbom_package_names, (
            f"Expected package {expected_package} not found in SBOM."
        )
