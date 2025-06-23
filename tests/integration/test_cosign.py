from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci.cosign import CosignClient
from tests.integration.conftest import ReferrersTagOCIClient


@pytest.fixture()
def make_image(oci_client: ReferrersTagOCIClient) -> Any:
    async def _make_image(name: str, tag: str) -> Image:
        return await oci_client.create_image(name, tag)

    return _make_image


@pytest_asyncio.fixture()
async def image_with_empty_sbom(
    oci_client: ReferrersTagOCIClient, make_image: Any
) -> Image:
    sbom = b"{}"
    image = await make_image("empty-sbom", "tag")
    await oci_client.attach_sbom(image, "spdx", sbom)
    return image


@pytest_asyncio.fixture()
async def image_with_no_sbom(make_image: Any) -> Image:
    return await make_image("no-sbom", "tag")


@pytest.mark.asyncio
async def test_cosign_fetch_sbom(image_with_empty_sbom: Image) -> None:
    cosign = CosignClient(Path(""))
    sbom = await cosign.fetch_sbom(image_with_empty_sbom)
    assert sbom.doc == {}


@pytest.mark.asyncio
async def test_cosign_fetch_sbom_no_sbom(image_with_no_sbom: Image) -> None:
    cosign = CosignClient(Path(""))
    with pytest.raises(SBOMError):
        await cosign.fetch_sbom(image_with_no_sbom)


@pytest.mark.asyncio
async def test_cosign_fetch_sbom_no_image() -> None:
    cosign = CosignClient(Path(""))
    image = Image(repository="no-repo", digest="sha256:deadbeef")
    with pytest.raises(SBOMError):
        await cosign.fetch_sbom(image)
