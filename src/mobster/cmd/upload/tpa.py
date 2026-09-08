"""
TPA API client
"""

import contextlib
import itertools
import json
import logging
import os
from collections.abc import AsyncGenerator
from enum import Enum
from pathlib import Path

import aiofiles
import httpx

from mobster.cmd.upload.model import PaginatedSbomSummaryResult, SbomSummary
from mobster.cmd.upload.oidc import (
    OIDCClientCredentials,
    OIDCClientCredentialsClient,
    RetryExhaustedException,
)
from mobster.utils import get_tpa_ca

LOGGER = logging.getLogger(__name__)


class TPAAPIVersion(Enum):
    """
    Supported TPA API versions.
    """

    V2 = "v2"
    V3 = "v3"


class TPAError(Exception):
    """
    Base exception for TPA-related errors.
    """


class TPATransientError(TPAError):
    """
    Exception for transient TPA errors that may be retried.
    """


class TPAClient(OIDCClientCredentialsClient):
    """
    TPA API client with connection pooling support.

    Inherits async context manager behavior from OIDCClientCredentialsClient.
    Use with "async with" statement for proper resource management.

    Example:
        async with TPAClient(
            base_url="https://tpa.example.com",
            auth=auth_credentials
        ) as client:
            urn = await client.upload_sbom(path_to_sbom)
            sboms = client.list_sboms(query="name:my-app")
            async for sbom in sboms:
                await client.download_sbom(sbom.id, local_path)
    """

    def __init__(
        self,
        base_url: str,
        auth: OIDCClientCredentials | None,
        proxy: str | None = None,
        ssl_verify_ca: str | None = None,
    ):
        self.api_version: TPAAPIVersion = TPAAPIVersion.V2
        super().__init__(base_url, auth, proxy, ssl_verify_ca)

    async def __aenter__(self) -> "TPAClient":
        """
        Initialize the HTTP client for connection pooling.

        Returns:
            Self instance with initialized HTTP client
        """
        await super().__aenter__()
        self.api_version = await self._get_api_version()
        return self

    async def _get_api_version(self, retries: int = 3) -> TPAAPIVersion:
        """
        Gets the API version of the TPA instance.

        Returns:
            The found TPA version.
        """
        try:
            response = await self.get("openapi.json", retries=retries)
            paths = response.json().get("paths", [])
        except (
            httpx.HTTPError,
            RetryExhaustedException,
            TypeError,
            ValueError,
            AttributeError,
        ) as err:
            LOGGER.warning("Could not get API version! Defaulting to v2.", exc_info=err)
            return TPAAPIVersion.V2
        if any(path.startswith("/api/v3/") for path in paths):
            return TPAAPIVersion.V3
        return TPAAPIVersion.V2

    async def upload_sbom(
        self,
        sbom_filepath: Path,
        labels: dict[str, str] | None = None,
        retries: int = 3,
    ) -> str:
        """
        Upload SBOM via API.

        Args:
            sbom_filepath: filepath to SBOM data to upload
            labels: mapping of TPA label keys to label values for uploaded SBOMs
            retries: how many attempts for SBOM upload will be performed before failing,
                defaults to 3

        Raises:
            TPAError: If the upload fails with a non-transient status code
            TPATransientError: If the upload fails after exhausting retries for
                transient errors

        Returns:
            str: URN of the uploaded SBOM
        """
        if not labels:
            labels = {}

        url = f"api/{self.api_version.value}/sbom"
        params = {}

        if labels_params := TPAClient._get_labels_params(labels):
            params.update(labels_params)

        headers = {
            "content-type": "application/json",
            "content-length": str(sbom_filepath.stat().st_size),
        }
        try:
            response = await self.post(
                url,
                content=lambda: TPAClient._iter_sbom_file(sbom_filepath),
                headers=headers,
                params=params,
                retries=retries,
            )
            urn: str = json.loads(response.content)["id"]
            return urn
        except RetryExhaustedException as err:
            raise TPATransientError(
                "Retries exhausted for transient TPA errors"
            ) from err
        except httpx.HTTPStatusError as err:
            raise TPAError(
                f"Failed to upload to TPA with code: {err.response.status_code} and"
                f" message: {err.response.content.decode()}"
            ) from err
        except httpx.HTTPError as err:
            raise TPAError("HTTP request for upload failed") from err

    @staticmethod
    async def _iter_sbom_file(
        path: Path, chunk_size: int = 64 * 1024
    ) -> AsyncGenerator[bytes, None]:
        """
        Yield the SBOM file in chunks for streaming upload.

        Args:
            path: Path to the SBOM file.
            chunk_size: Size of each chunk in bytes. Defaults to 64 KiB.

        Yields:
            File content chunks.
        """
        async with aiofiles.open(path, "rb") as sbom_file:
            while chunk := await sbom_file.read(chunk_size):
                yield chunk

    async def list_sboms(
        self, query: str, sort: str, page_size: int = 50
    ) -> AsyncGenerator[SbomSummary, None]:
        """
        List SBOMs objects from TPA API based on query and sort parameters.

        The method iterates over pages from the API response and yields `SbomSummary`
        objects. A method stops when there are no more SBOMs to process.

        Args:
            query (str): A query string to filter SBOMs.
            sort (str): A sort string to order the results.
            page_size (int, optional): A size of a page for paginated reqeust.
            Defaults to 50.


        Yields:
            AsyncGenerator[SbomSummary, None]: A generator yielding `SbomSummary`
            objects.
        """
        url = f"api/{self.api_version.value}/sbom"
        for page in itertools.count(start=0):
            params = {
                "q": query,
                "sort": sort,
                "limit": page_size,
                "offset": page * page_size,
            }
            LOGGER.debug("Listing SBOMs with params: %s", params)
            response = await self.get(url, params=params)

            sbom_summary = PaginatedSbomSummaryResult.model_validate_json(
                response.content
            )
            if len(sbom_summary.items) == 0:
                LOGGER.debug("No more SBOMs found.")
                break
            for sbom in sbom_summary.items:
                yield sbom

    async def delete_sbom(self, sbom_id: str) -> httpx.Response:
        """
        Delete SBOM from TPA using its ID.

        Args:
            sbom_id (str): SBOM identifier to delete.

        Returns:
            httpx.Response: response from API.
        """
        url = f"api/{self.api_version.value}/sbom/{sbom_id}"
        try:
            response = await self.delete(url)
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 404:
                LOGGER.warning("SBOM %s not found for deletion.", sbom_id)
                return err.response
            raise
        return response

    async def download_sbom(self, sbom_id: str, path: Path) -> None:
        """
        Download SBOM from TPA using its ID and save it to the specified path.

        Args:
            sbom_id (str): A SBOM identifier to download.
            path (Path): A file path to save the downloaded SBOM.
        """
        url = f"api/{self.api_version.value}/sbom/{sbom_id}/download"
        LOGGER.debug("Downloading SBOM %s to %s", sbom_id, path)

        async with aiofiles.open(path, "wb") as f:
            async for chunk in self.stream("GET", url):
                await f.write(chunk)

        LOGGER.info("Successfully downloaded SBOM %s to %s", sbom_id, path)

    @staticmethod
    def _get_labels_params(labels: dict[str, str]) -> dict[str, str]:
        """
        Transform a mapping of label keys to label values to a form that httpx
        can parse and use.
        """
        return {f"labels.{key}": val for key, val in labels.items()}


@contextlib.asynccontextmanager
async def get_tpa_default_client(
    base_url: str,
) -> AsyncGenerator[TPAClient, None]:
    """
    Get a default TPA client with OIDC credentials.

    Args:
        base_url (str): Base URL for the TPA API.

    Returns:
        TPAClient: An instance of TPAClient.
    """
    auth = None
    if os.environ.get("MOBSTER_TPA_AUTH_DISABLE", "false").lower() != "true":
        auth = OIDCClientCredentials(
            token_url=os.environ["MOBSTER_TPA_SSO_TOKEN_URL"],
            client_id=os.environ["MOBSTER_TPA_SSO_ACCOUNT"],
            client_secret=os.environ["MOBSTER_TPA_SSO_TOKEN"],
        )

    async with TPAClient(
        base_url=base_url,
        auth=auth,
        ssl_verify_ca=get_tpa_ca(),
    ) as client:
        yield client
