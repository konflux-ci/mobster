"""A command execution module for regenerating SBOM documents."""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import aiofiles
from httpx import Response

from mobster import utils
from mobster.cli import parse_concurrency
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import TPAClient, get_tpa_default_client
from mobster.error import SBOMError
from mobster.release import ReleaseId
from mobster.tekton.component import ProcessComponentArgs, process_component_sboms
from mobster.tekton.product import ProcessProductArgs, process_product_sboms
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


class SbomType(Enum):
    """
    enum to represent SBOM entrypoint type (Product/Component)
    """
    PRODUCT = "Product"
    COMPONENT = "Component"
    UNKNOWN = "Unknown"


@dataclass
class RegenerateArgs:
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
        sbom_type: SBOMType (Product/Component) used for this regenerator
    """

    output_path: Path
    tpa_base_url: str
    s3_bucket_url: str
    mobster_versions: str
    concurrency: int
    tpa_retries: int
    dry_run: bool
    fail_fast: bool
    verbose: bool
    sbom_type: SbomType = SbomType.UNKNOWN


class SbomRegenerator:
    """ base regenerator class for SBM regeneration """

    def __init__(
            self,
            args: RegenerateArgs,
            sbom_type: SbomType = SbomType.UNKNOWN,
    ) -> None:
        self.args = args
        self.sbom_type = sbom_type
        self.regen_semaphore = asyncio.Semaphore(self.args.concurrency)
        self.s3_semaphore = asyncio.Semaphore(self.args.concurrency)
        self.s3_client = self.setup_s3_client()
        self.tpa_client = self.setup_tpa_client()

    async def regenerate_sboms(self) -> None:
        """
        regenerate the set of sboms indicated by the cli args
        """
        LOGGER.debug(f"--concurrency: {self.args.concurrency}")
        LOGGER.debug(f"--fail-fast: {self.args.fail_fast}")
        LOGGER.debug(f"--dry-run: {self.args.dry_run}")
        LOGGER.info(f"Searching for matching {self.sbom_type.value} SBOMs..")

        # query for relevant sboms, based on the CLI-provided mobster versions
        sboms = self.get_tpa_client().list_sboms(
            query=self.construct_query(), sort="ingested"
        )

        LOGGER.info(f"Regenerating {self.sbom_type.value} SBOMs..")
        regen_tasks = []
        async for sbom in sboms:
            LOGGER.debug(
                f"Regenerating {self.sbom_type.value} SBOM: {sbom.id} ({sbom.name})"
            )
            try:
                regen_tasks.append(self.regenerate_sbom(sbom))
            except SBOMError as e:
                LOGGER.error(e)
                if self.args.fail_fast:
                    sys.exit(1)

        await asyncio.gather(*regen_tasks)

        LOGGER.info(f"Finished {self.sbom_type.value} SBOM regeneration.")

    async def regenerate_sbom(
            self, sbom: SbomSummary
    ) -> None:
        """
        regenerate the given sbom (re-create it, upload it, then delete old version)
        """
        async with self.regen_semaphore:
            release_id = await self.get_release_id(sbom)
            if not release_id:
                return
            # gather related data from s3 bucket
            path_snapshot, path_release_data = await self.gather_s3_input_data(
                release_id
            )

            if not path_snapshot or not path_release_data:
                raise SBOMError(
                    f"No S3 bucket snapshot/release_data found for SBOM: {sbom.id}"
                )
            LOGGER.info(
                f"proceeding to regenerate SBOM: {sbom.id}  ({sbom.name})"
            )
            if self.args.dry_run:
                LOGGER.info(f"*Dry Run: 'generate' SBOM: {sbom.id} ({sbom.name})")
            else:
                await self.process_sboms(release_id, path_release_data, path_snapshot)

            if self.args.dry_run:
                LOGGER.info(
                    f"*Dry Run: 'delete' original SBOM: {sbom.id} ({sbom.name})"
                )
            else:
                # delete
                response_delete = await self.delete_sbom(sbom.id)
                # check delete status
                if response_delete.status_code != 200:
                    # delete failed, log and abort regeneration for this SBOM
                    raise SBOMError(
                        f"delete SBOM failed for SBOM: {sbom.id}, "
                        f"status: {response_delete.status_code}, "
                        f"message: {response_delete.text}"
                    )
                LOGGER.info(
                    f"Success: deleted original SBOM: {sbom.id} ({sbom.name})"
                )
                return

    async def get_release_id(self, sbom: SbomSummary) -> ReleaseId:
        """
        get the given SBOM's release_id
        """
        try:
            # check if the given summary already contains it
            release_id = self.extract_release_id(sbom.model_dump())
        except ValueError:
            # nothing found
            try:
                # download the complete SBOM and extract the release_id
                release_id = await self.download_and_extract_release_id(sbom)
            except ValueError as e:
                LOGGER.error(f"No ReleaseId found in SBOM {sbom.id}")
                raise SBOMError() from e
        return release_id

    @staticmethod
    def extract_release_id(sbom_dict: dict[str, Any]) -> ReleaseId:
        """ extract ReleaseId from the given SBOM dict """
        if "annotations" in sbom_dict:
            for annot in sbom_dict["annotations"]:
                if "release_id=" in annot["comment"]:
                    return ReleaseId(annot["comment"].partition("release_id=")[2])
        elif "properties" in sbom_dict:
            for prop in sbom_dict["properties"]:
                if prop["name"] == "release_id":
                    return ReleaseId(prop["value"])
        raise ValueError(f"No ReleaseId found in SBOM: {sbom_dict.get('id')}")

    async def download_and_extract_release_id(
        self, sbom: SbomSummary
    ) -> ReleaseId:
        """
        download the full SBOM represented by the given summary,
        then extract ReleaseId from it
        """
        name = utils.normalize_file_name(sbom.name)
        local_path = self.args.output_path / f"{name}.json"
        await self.get_tpa_client().download_sbom(sbom.id, local_path)
        # allow retry, since larger volume of downloads occasionally
        # results in slightly delayed availability
        max_retries = 3
        for retry in range(1, max_retries):
            try:
                async with aiofiles.open(local_path, encoding="utf-8") as f:
                    json_str_contents = await f.read()
                    sbom_dict = json.loads(json_str_contents)
                    return self.extract_release_id(sbom_dict)
            except FileNotFoundError:
                LOGGER.warning(f"'{local_path}' not found.")
            except json.JSONDecodeError:
                LOGGER.warning(f"Invalid JSON in '{local_path}'.")
            if retry < max_retries:
                # briefly wait, then try again
                await asyncio.sleep(0.5)
                continue
        raise ValueError(f"Unable to extract ReleaseId from {local_path}")

    def construct_query(self) -> str:
        """
        construct a TPA query based on the cli-supplied mobster versions arg
        """
        versions = "|".join(
            f"Tool: Mobster-{str(v).strip()}"
            for v in self.args.mobster_versions.split(",")
        )
        query = f"authors~{versions}"
        LOGGER.info(f"query: {query}")
        return query

    def get_s3_client(self) -> S3Client:
        """ get the currently configured S3Client """
        return self.s3_client

    def get_tpa_client(self) -> TPAClient:
        """ get the currently configured TPAClient """
        return self.tpa_client

    def setup_s3_client(self) -> S3Client:
        """ setup a S3Client """
        bucket, endpoint_url = self.parse_s3_bucket_url(self.args.s3_bucket_url)
        s3_client = S3Client(
            bucket=bucket,
            access_key=os.environ["MOBSTER_S3_ACCESS_KEY"],
            secret_key=os.environ["MOBSTER_S3_SECRET_KEY"],
            concurrency_limit=self.args.concurrency,
            endpoint_url=endpoint_url
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
        match_bucket_name = re.search('//(.+?).s3', s3_bucket_url)
        endpoint_url = s3_bucket_url
        bucket_name = ""
        if match_bucket_name:
            bucket_name = match_bucket_name.group(1)
            endpoint_url = s3_bucket_url.replace(
                f"{bucket_name}.", ""
            )
        return bucket_name, endpoint_url

    def setup_tpa_client(self) -> TPAClient:
        """ setup a TPAClient """
        return get_tpa_default_client(self.args.tpa_base_url)

    async def gather_s3_input_data(self, rid: ReleaseId) -> tuple[Path, Path]:
        """ fetch snapshot and release data from S3 for the given ReleaseId """
        LOGGER.debug(f"gathering input data for release_id: '{rid}'")
        path_snapshot = (
            self.args.output_path / S3Client.snapshot_prefix / f"{rid}.snapshot.json"
        )
        path_release_data = (
            self.args.output_path
            / S3Client.release_data_prefix
            / f"{rid}.release_data.json"
        )
        async with self.s3_semaphore:
            if not await self.get_s3_client().get_snapshot(
                    path_snapshot,
                    rid
            ):
                raise ValueError(
                    f"No snapshot found for ReleaseId: {str(rid)}"
                )
            if not await self.get_s3_client().get_release_data(
                    path_release_data,
                    rid
            ):
                raise ValueError(
                    f"No release data found for ReleaseId: {str(rid)}"
                )
        LOGGER.info(f"input data gathered from S3 bucket, for release_id: {rid}")
        return path_snapshot, path_release_data

    async def process_sboms(
        self, release_id: ReleaseId, path_release_data: Path, path_snapshot: Path
    ) -> None:
        """
        invoke the relevant tekton SBOM generation function,
        based on which cli-called entrypoint was used
        """
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
                    tpa_retries=self.args.tpa_retries,
                    upload_concurrency=self.args.concurrency,
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
                    tpa_retries=self.args.tpa_retries,
                    upload_concurrency=self.args.concurrency,
                )
            )

    async def delete_sbom(self, sbom_id: str) -> Response:
        """ delete the given SBOM, using the TPA client """
        response = await self.get_tpa_client().delete_sbom(sbom_id)
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
    prepare_output_paths(args.output_path)

    LOGGER.debug(args)

    return RegenerateArgs(
        output_path=args.output_path,
        tpa_base_url=args.tpa_base_url,
        s3_bucket_url=args.s3_bucket_url,
        mobster_versions=args.mobster_versions,
        concurrency=args.concurrency,
        tpa_retries=args.tpa_retries,
        dry_run=args.dry_run,
        fail_fast=not args.non_fail_fast,
        verbose=args.verbose,
    )  # pylint:disable=duplicate-code


def prepare_output_paths(output_path: Path) -> None:
    """ ensure cli-specified output paths exist for use by the regenerator """
    # prepare output_path subdirs
    (output_path / S3Client.release_data_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / S3Client.snapshot_prefix).mkdir(parents=True, exist_ok=True)


def add_args(parser: ArgumentParser) -> None:
    """
    Add command line arguments to the parser.

    Args:
        parser: argument parser to add commands to
    """
    parser.add_argument(
        "--output-path",
        type=Path,
        required=True,
        help="Path to the output directory. "
        "If it doesn't exist, it will be automatically created.",
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

    parser.add_argument(
        "--dry-run",
        type=bool,
        default=False,
        help="Run in 'dry run' only mode (skips destructive TPA IO)",
    )

    parser.add_argument(
        "--non-fail-fast",
        type=bool,
        default=False,
        help="don't fail and exit on first regen error",
    )

    parser.add_argument(
        "--verbose",
        type=bool,
        default=False,
        help="Run in verbose mode (additional logs/trace)",
    )
