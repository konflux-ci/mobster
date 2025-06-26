"""
TPA API client
"""

import logging
from collections.abc import Generator
from pathlib import Path

import aiofiles
import httpx

from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.oidc import OIDCClientCredentialsClient

LOGGER = logging.getLogger(__name__)


class TPAClient(OIDCClientCredentialsClient):
    """
    TPA API client
    """

    async def upload_sbom(self, sbom_filepath: Path) -> httpx.Response:
        """
        Upload SBOM via API.

        Args:
            sbom_filepath(str): filepath to SBOM data to upload

        Returns:
            Any: Response from API
        """
        url = "api/v2/sbom"
        headers = {"content-type": "application/json"}
        async with aiofiles.open(sbom_filepath, "rb") as sbom_file:
            file_content = await sbom_file.read()
            response = await self.post(
                url,
                content=file_content,
                headers=headers,
            )
            return response

    async def list_sboms(
        self, query: str, sort: str
    ) -> Generator[SbomSummary, None, None]:
        """List sboms"""
        raise NotImplementedError()

    async def delete_sbom(self, sbom_id: int) -> None:
        """Delete sbom"""
        raise NotImplementedError()

    async def download_sbom(self, sbom_id: str, path: Path) -> None:
        """Download sbom"""
        # https://www.python-httpx.org/quickstart/#streaming-responses
        raise NotImplementedError()
