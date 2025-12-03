"""Module for regenerating invalid SBOMs created by a specific Mobster version"""

import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any

import aiofiles
from httpx import HTTPStatusError, RequestError, Response

from mobster import utils
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import get_tpa_default_client
from mobster.error import SBOMError
from mobster.regenerate.base import (
    CommonArgs,
    MissingReleaseIdError,
    SbomRegenerator,
)
from mobster.release import ReleaseId

LOGGER = logging.getLogger(__name__)


@dataclass
class RegenerateArgs(CommonArgs):  # pylint: disable=R0902
    """
    Arguments for SBOM regeneration.

    Attributes:
        mobster_versions: Comma separated list of mobster versions to query for
                          e.g.:   0.2.1,0.5.0
        ignore_missing_releaseid: Ignore (and don't fail on) any SBOM which
                                  doesn't contain a ReleaseId
        tpa_page_size: paging size (how many SBOMs) for query response sets
    """

    mobster_versions: str
    tpa_page_size: int
    ignore_missing_releaseid: bool


class FaultySbomRegenerator(SbomRegenerator):
    """
    This class regenerates SBOMs for Mobster's specific version in case
    of a bug in the specified version.
    """

    args: RegenerateArgs

    async def populate_releases(self) -> None:
        """
        regenerate the set of sboms indicated by the cli args
        """
        LOGGER.info("Searching for matching %s SBOMs..", self.sbom_type.value)
        # query for relevant sboms, based on the CLI-provided mobster versions
        async with get_tpa_default_client(self.args.tpa_base_url) as tpa_client:
            sboms = tpa_client.list_sboms(
                query=self.construct_query(),
                sort="ingested",
                page_size=self.args.tpa_page_size,
            )

            LOGGER.info("Gathering ReleaseIds for %s SBOMs.", self.sbom_type.value)
            tasks_gather_release_ids = []
            async for sbom in sboms:
                tasks_gather_release_ids.append(self.organize_sbom_by_release_id(sbom))

            try:
                await asyncio.gather(*tasks_gather_release_ids)
            except SBOMError as e:
                LOGGER.error(e)
                if self.args.fail_fast:
                    sys.exit(1)

        LOGGER.info(
            "Finished gathering ReleaseIds for %s SBOMs.", len(tasks_gather_release_ids)
        )

    async def delete_sbom(self, sbom_id: str) -> Response:
        """delete the given SBOM, using the TPA client"""
        async with get_tpa_default_client(self.args.tpa_base_url) as tpa_client:
            response = await tpa_client.delete_sbom(sbom_id)
        return response

    async def download_and_extract_release_id(self, sbom: SbomSummary) -> ReleaseId:
        """
        download the full SBOM represented by the given summary,
        then extract ReleaseId from it
        """
        async with self.semaphore:
            file_name = utils.normalize_file_name(sbom.id)
            local_path = self.args.output_path / f"{file_name}.json"
            # allow retry on download
            max_download_retries = 5
            for retry in range(1, max_download_retries):
                try:
                    async with get_tpa_default_client(
                        self.args.tpa_base_url
                    ) as tpa_client:
                        await tpa_client.download_sbom(sbom.id, local_path)
                    # allow read retry, since larger volume of downloads occasionally
                    # results in slightly delayed availability
                    max_read_retries = 3
                    for read_retry in range(1, max_read_retries):
                        try:
                            async with aiofiles.open(local_path, encoding="utf-8") as f:
                                json_str_contents = await f.read()
                                sbom_dict = json.loads(json_str_contents)
                                try:
                                    return self.extract_release_id(sbom_dict)
                                except MissingReleaseIdError as mr_err:
                                    LOGGER.warning(str(mr_err))
                                    LOGGER.debug(sbom_dict)
                        except FileNotFoundError:  # pragma: no cover
                            LOGGER.warning("'%s' not found.", str(local_path))
                        except json.JSONDecodeError:  # pragma: no cover
                            LOGGER.warning("Invalid JSON in '%s'.", str(local_path))
                        if read_retry < max_read_retries:
                            # briefly wait, then try again
                            await asyncio.sleep(0.5 * read_retry)
                            continue
                    # successful download & read, no need to retry
                    break
                except (RequestError, HTTPStatusError) as e:
                    msg = f"Download was unsuccessful for '{local_path}' ({str(e)})."
                    if retry < max_download_retries:
                        # briefly wait, then try again
                        await asyncio.sleep(0.5 * retry)
                        LOGGER.debug("retry %s... (%s)", retry, msg)
                        continue
                    LOGGER.error(msg)
                    raise SBOMError(msg) from e

            # no ReleaseId was found
            raise MissingReleaseIdError(
                f"Unable to extract ReleaseId from {local_path}"
            )

    def construct_query(self) -> str:
        """
        construct a TPA query based on the cli-supplied mobster versions arg
        """
        versions = "|".join(
            f"Tool: Mobster-{str(v).strip()}"
            for v in self.args.mobster_versions.split(",")
        )
        query = f"authors~{versions}"
        LOGGER.debug("query: %s", query)
        return query

    @staticmethod
    def extract_release_id(sbom_dict: dict[str, Any]) -> ReleaseId:
        """extract ReleaseId from the given SBOM dict"""
        if "annotations" in sbom_dict:
            for annot in sbom_dict["annotations"]:
                if "release_id=" in annot["comment"]:
                    return ReleaseId(annot["comment"].partition("release_id=")[2])
        elif "properties" in sbom_dict:
            for prop in sbom_dict["properties"]:
                if prop["name"] == "release_id":
                    return ReleaseId(prop["value"])
        raise MissingReleaseIdError(
            f"No ReleaseId found in SBOM: {sbom_dict.get('id')}"
        )

    async def organize_sbom_by_release_id(self, sbom: SbomSummary) -> None:
        """get the SBOM's ReleaseId and add it to that release group for regen"""
        LOGGER.debug("Gathering ReleaseId for SBOM: %s", sbom.id)
        try:
            release_id = await self.download_and_extract_release_id(sbom)
            self.sbom_release_groups.add(release_id)
            LOGGER.debug(
                "Finished gathering ReleaseId (%s) for SBOM: %s", release_id, sbom.id
            )
        except MissingReleaseIdError as e:
            if self.args.ignore_missing_releaseid:
                LOGGER.debug(str(e))
                return
            LOGGER.error(str(e))
            raise SBOMError from e
