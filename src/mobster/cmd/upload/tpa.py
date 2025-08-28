"""
TPA API client
"""

import itertools
import json
import logging
import os
from collections.abc import AsyncGenerator
from pathlib import Path

import aiofiles
import httpx

from mobster.cmd.upload.model import PaginatedSbomSummaryResult, SbomSummary
from mobster.cmd.upload.oidc import (
    OIDCClientCredentials,
    OIDCClientCredentialsClient,
    RetryExhaustedException,
)

LOGGER = logging.getLogger(__name__)


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
    TPA API client
    """

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

        url = "api/v2/sbom"
        params = {}

        if labels_params := TPAClient._get_labels_params(labels):
            params.update(labels_params)

        headers = {"content-type": "application/json"}
        async with aiofiles.open(sbom_filepath, "rb") as sbom_file:
            file_content = await sbom_file.read()
            try:
                response = await self.post(
                    url,
                    content=file_content,
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
        url = "api/v2/sbom"
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
        url = f"api/v2/sbom/{sbom_id}"
        response = await self.delete(url)
        return response

    async def download_sbom(self, sbom_id: str, path: Path) -> None:
        """
        Download SBOM from TPA using its ID and save it to the specified path.

        Args:
            sbom_id (str): A SBOM identifier to download.
            path (Path): A file path to save the downloaded SBOM.
        """
        url = f"api/v2/sbom/{sbom_id}/download"
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


def get_tpa_default_client(
    base_url: str,
) -> TPAClient:
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
    tpa_client = TPAClient(
        base_url=base_url,
        auth=auth,
    )
    return tpa_client
