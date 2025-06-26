from pathlib import Path

import pytest
import pytest_asyncio

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci.cosign import CosignClient
from tests.integration.oci_client import ReferrersTagOCIClient


@pytest_asyncio.fixture()
async def image_with_empty_sbom(oci_client: ReferrersTagOCIClient) -> Image:
    sbom = b"{}"
    image = await oci_client.create_image("emtpy-sbom", "tag")
    await oci_client.attach_sbom(image, "spdx", sbom)
    return image


@pytest_asyncio.fixture()
async def image_with_no_sbom(oci_client: ReferrersTagOCIClient) -> Image:
    return await oci_client.create_image("no-sbom", "tag")


@pytest.mark.asyncio
async def test_cosign_fetch_sbom(image_with_empty_sbom: Image) -> None:
    """
    Test fetching an SBOM from an image that has one.

    Args:
        image_with_empty_sbom: Image fixture with an empty SBOM.
    """
    cosign = CosignClient(Path(""))
    sbom = await cosign.fetch_sbom(image_with_empty_sbom)
    assert sbom.doc == {}


@pytest.mark.asyncio
async def test_cosign_fetch_sbom_no_sbom(image_with_no_sbom: Image) -> None:
    """
    Test fetching an SBOM from an image that has none.

    Args:
        image_with_no_sbom: Image fixture with no SBOM.
    """
    cosign = CosignClient(Path(""))
    with pytest.raises(SBOMError):
        await cosign.fetch_sbom(image_with_no_sbom)


@pytest.mark.asyncio
async def test_cosign_fetch_sbom_no_image() -> None:
    """
    Test fetching an SBOM from a non-existent image.
    """
    cosign = CosignClient(Path(""))
    image = Image(repository="no-repo", digest="sha256:deadbeef")
    with pytest.raises(SBOMError):
        await cosign.fetch_sbom(image)
