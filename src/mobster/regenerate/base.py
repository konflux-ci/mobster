"""A command execution module for regenerating SBOM documents."""

import argparse
import asyncio
import atexit
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from argparse import ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from subprocess import CalledProcessError
from typing import Any

import aiofiles
from httpx import HTTPStatusError, RequestError, Response

from mobster import utils
from mobster.cli import parse_concurrency
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import get_tpa_default_client
from mobster.error import SBOMError
from mobster.oci.cosign import CosignConfig
from mobster.release import ReleaseId
from mobster.tekton.component import ProcessComponentArgs, process_component_sboms
from mobster.tekton.product import ProcessProductArgs, process_product_sboms
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)

""" directory prefix for (re)generated SBOMs """
GENERATED_SBOMS_PREFIX = "sbom"


class SbomType(Enum):
    """
    enum to represent SBOM entrypoint type (Product/Component)
    """

    PRODUCT = "Product"
    COMPONENT = "Component"


class MissingReleaseIdError(ValueError):
    """
    Exception class for cases where ReleaseId is not found in an SBOM.
    """


@dataclass
class RegenerateArgs:  # pylint: disable=R0902
    """
    Arguments for SBOM regeneration.

    Attributes:
        output_path: Path to the output files.
        tpa_base_url: path to snapshot spec file
        s3_bucket_url: url of the TPA instance to use
        mobster_versions: Comma separated list of mobster versions to query for
                          e.g.:   0.2.1,0.5.0
        concurrency: concurrency limit for S3 client (non-zero integer)
        tpa_retries: total number of attempts for TPA requests
        dry_run: Run in 'dry run' only mode (skips destructive TPA IO)
        fail_fast: fail and exit on first regen error (default: True)
        verbose: Run in verbose mode (additional logs/trace)
        ignore_missing_releaseid: Ignore (and don't fail on) any SBOM which
                                  doesn't contain a ReleaseId
        tpa_page_size: paging size (how many SBOMs) for query response sets
    """

    output_path: Path
    tpa_base_url: str
    s3_bucket_url: str
    mobster_versions: str
    concurrency: int
    tpa_retries: int
    tpa_page_size: int
    dry_run: bool
    fail_fast: bool
    ignore_missing_releaseid: bool
    verbose: bool


class SbomRegenerator:
    """base regenerator class for SBM regeneration"""

    def __init__(
        self,
        args: RegenerateArgs,
        sbom_type: SbomType,
    ) -> None:
        self.args = args
        self.sbom_type = sbom_type
        self.semaphore = asyncio.Semaphore(self.args.concurrency)
        self.s3_client = self.setup_s3_client()
        self.sbom_release_groups: dict[str, list[str]] = defaultdict(list)

    async def regenerate_sboms(self) -> None:
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

        LOGGER.info(
            "Running regenerate for %s release groups..", len(self.sbom_release_groups)
        )
        if self.args.verbose:
            LOGGER.debug("release groups: %s", self.sbom_release_groups)
        await self.regenerate_release_groups()
        LOGGER.info(
            "Finished regeneration for %s release groups.",
            len(self.sbom_release_groups),
        )

    async def organize_sbom_by_release_id(self, sbom: SbomSummary) -> None:
        """get the SBOM's ReleaseId and add it to that release group for regen"""
        LOGGER.debug("Gathering ReleaseId for SBOM: %s", sbom.id)
        try:
            release_id = await self.download_and_extract_release_id(sbom)
            self.sbom_release_groups[str(release_id)].append(sbom.id)
            LOGGER.debug(
                "Finished gathering ReleaseId (%s) for SBOM: %s", release_id, sbom.id
            )
        except MissingReleaseIdError as e:
            if self.args.ignore_missing_releaseid:
                LOGGER.debug(str(e))
                return
            LOGGER.error(str(e))
            raise SBOMError from e

    async def regenerate_release_groups(self) -> None:
        """walk the set of release groups, and regenerate each release"""
        LOGGER.info("Regenerating %s release groups..", self.sbom_type.value)
        regen_tasks = []
        for release_id in self.sbom_release_groups:
            regen_tasks.append(self.regenerate_sbom_release(ReleaseId(release_id)))
        await asyncio.gather(*regen_tasks)
        LOGGER.info("Finished regenerating %s release groups.", self.sbom_type.value)

    async def regenerate_sbom_release(self, release_id: ReleaseId) -> None:
        """
        regenerate the given sbom release
        (re-create it, upload it, then delete old version)
        """
        try:
            async with self.semaphore:
                # gather related data from s3 bucket
                path_snapshot, path_release_data = await self.gather_s3_input_data(
                    release_id
                )

                if not path_snapshot or not path_release_data:
                    raise SBOMError(
                        f"No S3 bucket snapshot/release_data found "
                        f"for SBOM release: {str(release_id)}"
                    )
                LOGGER.debug("Generate SBOM release: %s", str(release_id))
                await self.process_sboms(release_id, path_release_data, path_snapshot)
        except SBOMError as e:
            if self.args.fail_fast:
                raise e
            LOGGER.warning(str(e))

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
                        except FileNotFoundError:
                            LOGGER.warning("'%s' not found.", str(local_path))
                        except json.JSONDecodeError:
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
                    # raise SBOMError to stop overall script execution
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

    def get_s3_client(self) -> S3Client:
        """get the currently configured S3Client"""
        return self.s3_client

    def setup_s3_client(self) -> S3Client:
        """setup a S3Client"""
        bucket, endpoint_url = self.parse_s3_bucket_url(self.args.s3_bucket_url)
        s3_client = S3Client(
            bucket=bucket,
            access_key=os.environ["AWS_ACCESS_KEY_ID"],
            secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
            concurrency_limit=self.args.concurrency,
            endpoint_url=endpoint_url,
        )
        return s3_client

    @staticmethod
    def parse_s3_bucket_url(s3_bucket_url: str) -> tuple[str, str]:
        """
        parse the s3-bucket-url arg into bucket name and endpoint

        (test mocks may provide malformed URLs; no problem to allow these,
          since any legitimately malformed URLs from the CLI will simply result
          in an exit with error, on initial S3 request attempt)
        """
        match_bucket_name = re.search("//(.+?).s3", s3_bucket_url)
        endpoint_url = s3_bucket_url
        bucket_name = ""
        if match_bucket_name:
            bucket_name = match_bucket_name.group(1)
            endpoint_url = s3_bucket_url.replace(f"{bucket_name}.", "")
        return bucket_name, endpoint_url

    async def gather_s3_input_data(self, rid: ReleaseId) -> tuple[Path, Path]:
        """fetch snapshot and release data from S3 for the given ReleaseId"""
        LOGGER.debug("gathering input data for release_id: '%s'", rid)
        path_snapshot = (
            self.args.output_path / S3Client.snapshot_prefix / f"{rid}.snapshot.json"
        )
        path_release_data = (
            self.args.output_path
            / S3Client.release_data_prefix
            / f"{rid}.release_data.json"
        )
        max_download_retries = 5
        for retry in range(1, max_download_retries):
            # use timeout to avoid hung responses
            try:
                got_snapshot = await asyncio.wait_for(
                    self.get_s3_client().get_snapshot(path_snapshot, rid), 5
                )
                got_release_data = await asyncio.wait_for(
                    self.get_s3_client().get_release_data(path_release_data, rid), 5
                )
                if got_snapshot and got_release_data:
                    break
                LOGGER.warning(
                    "S3 gather (attempt %s) failed for ReleaseId: %s", retry, str(rid)
                )
            except (TimeoutError, ValueError) as e:
                if retry < max_download_retries:
                    await asyncio.sleep(0.5 * retry)
                    continue
                LOGGER.error(
                    "S3 gather max retries exceeded (%s) for ReleaseId: %s",
                    retry,
                    str(rid),
                )
                raise SBOMError from e
        LOGGER.debug("input data gathered from S3 bucket, for release_id: %s", rid)
        # ensure s3 client has actually completed download and written the files
        await asyncio.sleep(0.5)
        return path_snapshot, path_release_data

    async def process_sboms(
        self, release_id: ReleaseId, path_release_data: Path, path_snapshot: Path
    ) -> None:
        """
        invoke the relevant tekton SBOM generation function,
        based on which cli-called entrypoint was used
        """
        try:
            if self.sbom_type == SbomType.PRODUCT:
                await process_product_sboms(
                    ProcessProductArgs(
                        release_data=path_release_data,
                        concurrency=self.args.concurrency,
                        data_dir=self.args.output_path,
                        snapshot_spec=path_snapshot,
                        atlas_api_url=self.args.tpa_base_url,
                        retry_s3_bucket=self.args.s3_bucket_url,
                        release_id=release_id,
                        labels={},
                        result_dir=self.args.output_path,
                        sbom_path=self.args.output_path
                        / GENERATED_SBOMS_PREFIX
                        / f"{str(release_id)}.json",
                        atlas_retries=self.args.tpa_retries,
                        upload_concurrency=self.args.concurrency,
                        skip_upload=self.args.dry_run,
                    )
                )
                #  release_notes, snapshot, release_id
            elif self.sbom_type == SbomType.COMPONENT:
                await process_component_sboms(
                    ProcessComponentArgs(
                        data_dir=self.args.output_path,
                        snapshot_spec=path_snapshot,
                        atlas_api_url=self.args.tpa_base_url,
                        retry_s3_bucket=self.args.s3_bucket_url,
                        release_id=release_id,
                        labels={},
                        augment_concurrency=self.args.concurrency,
                        result_dir=self.args.output_path,
                        atlas_retries=self.args.tpa_retries,
                        upload_concurrency=self.args.concurrency,
                        attestation_concurrency=self.args.concurrency,
                        skip_upload=self.args.dry_run,
                        cosign_config=CosignConfig(),
                    )
                )
        except CalledProcessError as e:
            raise SBOMError from e

    async def delete_sbom(self, sbom_id: str) -> Response:
        """delete the given SBOM, using the TPA client"""
        async with get_tpa_default_client(self.args.tpa_base_url) as tpa_client:
            response = await tpa_client.delete_sbom(sbom_id)
        return response


def parse_args() -> RegenerateArgs:
    """
    Parse command line arguments for product SBOM processing.

    Returns:
        ProcessProductArgs: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()

    path_output_dir = prepare_output_paths(args.output_dir)

    LOGGER.debug(args)

    return RegenerateArgs(
        output_path=path_output_dir,
        tpa_base_url=args.tpa_base_url,
        s3_bucket_url=args.s3_bucket_url,
        mobster_versions=args.mobster_versions,
        concurrency=args.concurrency,
        tpa_retries=args.tpa_retries,
        tpa_page_size=args.tpa_page_size,
        dry_run=args.dry_run,
        fail_fast=not args.non_fail_fast,
        ignore_missing_releaseid=args.ignore_missing_releaseid,
        verbose=args.verbose,
    )  # pylint:disable=duplicate-code


def prepare_output_paths(output_dir: str) -> Path:
    """ensure cli-specified output paths exist for use by the regenerator"""
    if not output_dir:
        # create it as a temporary directory
        output_dir = tempfile.mkdtemp()
        # remove it on exit
        atexit.register(lambda: shutil.rmtree(output_dir))
    output_path = Path(output_dir)
    LOGGER.debug("output path: %s", output_path)
    # prepare output_path subdirs
    (output_path / S3Client.release_data_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / S3Client.snapshot_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / GENERATED_SBOMS_PREFIX).mkdir(parents=True, exist_ok=True)
    return output_path


def add_args(parser: ArgumentParser) -> None:
    """
    Add command line arguments to the parser.

    Args:
        parser: argument parser to add commands to
    """
    parser.add_argument(
        "--output-dir",
        type=str,
        required=False,
        help="Path to the output directory. "
        "If it doesn't exist, it will be automatically created. "
        "If not specified, a TemporaryDirectory will be created.",
    )

    parser.add_argument(
        "--tpa-base-url",
        type=str,
        required=True,
        help="URL of the TPA server",
    )

    parser.add_argument(
        "--s3-bucket-url",
        type=str,
        required=True,
        help="AWS S3 bucket URL",
    )

    parser.add_argument(
        "--mobster-versions",
        type=str,
        required=True,
        help="Comma separated list of mobster versions to query for, "
        "e.g.:  0.2.1,0.5.0",
    )

    parser.add_argument(
        "--concurrency",
        type=parse_concurrency,
        default=8,
        help="concurrency limit for S3 client (non-zero integer)",
    )

    parser.add_argument(
        "--tpa-retries",
        type=int,
        default=1,
        help="total number of attempts for TPA requests",
    )

    # int
    parser.add_argument(
        "--tpa-page-size",
        type=int,
        default=50,
        help="paging size (how many SBOMs) for query response sets",
    )

    # bool
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in 'dry run' only mode (skips destructive TPA IO)",
    )

    # bool
    parser.add_argument(
        "--non-fail-fast",
        action="store_true",
        help="Don't fail and exit on first regen error",
    )

    # bool
    parser.add_argument(
        "--ignore-missing-releaseid",
        action="store_true",
        help="Ignore (and don't fail on) any SBOM which is missing ReleaseId",
    )

    # bool
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Run in verbose mode (additional logs/trace)",
    )
