from pathlib import Path

import pytest
import pytest_asyncio

from mobster.image import Image
from mobster.oci.cosign import CosignClient
from tests.integration.conftest import ReferrersTagOCIClient


@pytest.fixture()
def registry_url() -> str:
    return "http://localhost:9000"


@pytest.fixture
def oci_client(registry_url: str) -> ReferrersTagOCIClient:
    return ReferrersTagOCIClient(registry_url)


@pytest_asyncio.fixture()
async def image_with_empty_sbom(oci_client: ReferrersTagOCIClient) -> Image:
    sbom = b"{}"
    image_reference = await oci_client.prepare_sbom("name", "tag", "spdx", sbom)
    return Image.from_oci_artifact_reference(image_reference)


@pytest.mark.asyncio
async def test_cosign_fetch_sbom(image_with_empty_sbom: Image) -> None:
    cosign = CosignClient(Path(""))
    sbom = await cosign.fetch_sbom(image_with_empty_sbom)
    assert sbom.doc == {}
