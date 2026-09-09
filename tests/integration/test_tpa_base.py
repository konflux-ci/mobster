import pytest

from mobster.cmd.upload.tpa import TPAAPIVersion, TPAClient


@pytest.mark.asyncio
async def test_tpa_version(tpa_client: TPAClient) -> None:
    assert await tpa_client._get_api_version() is TPAAPIVersion.V2
