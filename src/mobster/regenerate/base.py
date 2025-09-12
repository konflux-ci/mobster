"""A command execution module for regenerating SBOM documents."""

import argparse
import json
import logging
import os
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from mobster import utils
from mobster.cli import parse_concurrency
from mobster.cmd.download.download_tpa import get_tpa_default_client
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import TPAClient
from mobster.error import SBOMError
from mobster.release import ReleaseId
from mobster.tekton.component import ProcessComponentArgs, process_component_sboms
from mobster.tekton.product import ProcessProductArgs, process_product_sboms
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


class SbomType(Enum):
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
    def __init__(
        self, args: RegenerateArgs, sbom_type: SbomType = SbomType.UNKNOWN
    ) -> None:
        self.args = args
        self.sbom_type = sbom_type
        self.tpa_client: TPAClient | None = None
        self.s3_client: S3Client | None = None

    async def regenerate_sboms(self) -> None:
        """
        regenerate the set of sboms indicated by the cli args
        """
        LOGGER.debug(f"--fail-fast: {self.args.fail_fast}")
        LOGGER.debug(f"--dry-run: {self.args.dry_run}")
        LOGGER.info(f"Searching for matching {self.sbom_type.value} SBOMs..")

        self.tpa_client = get_tpa_default_client(self.args.tpa_base_url)
        self.s3_client = self.get_s3_client()

        # query for relevant sboms, based on the CLI-provided mobster versions
        sboms = self.tpa_client.list_sboms(
            query=self.construct_query(), sort="ingested"
        )

        LOGGER.info(f"Regenerating {self.sbom_type.value} SBOMs..")

        async for sbom in sboms:
            LOGGER.debug(
                f"Regenerating {self.sbom_type.value} SBOM: {sbom.id} ({sbom.name})"
            )
            try:
                await self.regenerate_sbom(sbom)
            except SBOMError as e:
                LOGGER.error(e)
                if self.args.fail_fast:
                    exit(1)

        LOGGER.info(f"Finished {self.sbom_type.value} SBOM regeneration.")

    async def regenerate_sbom(self, sbom: SbomSummary) -> None:
        """
        regenerate the given sbom (re-create it, upload it, then delete old version)
        """
        release_id = await self.get_release_id(sbom)
        if not release_id:
            return
        # gather related data from s3 bucket
        path_snapshot, path_release_data = await self.gather_s3_input_data(release_id)
        LOGGER.info(f"proceeding to regenerate SBOM: {sbom.id}  ({sbom.name})")
        if self.args.dry_run:
            LOGGER.info(f"*Dry Run: 'generate' SBOM: {sbom.id} ({sbom.name})")
        else:
            await self.process_sboms(release_id.id, path_release_data, path_snapshot)

        if self.args.dry_run:
            LOGGER.info(f"*Dry Run: 'delete' original SBOM: {sbom.id} ({sbom.name})")
        else:
            # delete
            response_delete = await self.tpa_client.delete(sbom.id)
            # check delete status
            if response_delete.status_code != 200:
                # delete failed, log and abort regeneration for this SBOM
                raise SBOMError(
                    f"delete SBOM failed for SBOM: {sbom.id}, "
                    f"status: {response_delete.status_code}, "
                    f"message: {response_delete.text}"
                )
            LOGGER.info(f"Success: deleted original SBOM: {sbom.id} ({sbom.name})")
            return

    async def get_release_id(self, sbom: SbomSummary):
        """
        get the given SBOM's release_id
        """
        # check if the given summary already contains it
        release_id = self.extract_release_id(sbom)
        if not release_id:
            # download the complete SBOM and extract the release_id
            release_id = await self.download_and_extract_release_id(sbom)
        return release_id

    @staticmethod
    def extract_release_id(sbom: SbomSummary) -> ReleaseId | None:
        if "annotations" in sbom:
            for annot in sbom["annotations"]:
                if "release_id=" in annot["comment"]:
                    return ReleaseId(annot["comment"].partition("release_id=")[2])
        elif "properties" in sbom:
            for prop in sbom["properties"]:
                if prop["name"] == "release_id":
                    return prop["value"]
        return None

    async def download_and_extract_release_id(
        self, sbom: SbomSummary
    ) -> ReleaseId | None:
        name = utils.normalize_file_name(sbom.name)
        local_path = self.args.output_path / f"{name}.json"
        await self.tpa_client.download_sbom(sbom.id, local_path)
        try:
            with open(local_path) as f:
                sbom = json.load(f)
        except FileNotFoundError:
            LOGGER.error(f"'{local_path}' not found.")
            return None
        except json.JSONDecodeError:
            LOGGER.error("Error: Invalid JSON in '{local_path_original}'.")
            return None
        return self.extract_release_id(sbom)

    def construct_query(self):
        versions = "|".join(
            f"Tool: Mobster-{str(v).strip()}"
            for v in self.args.mobster_versions.split(",")
        )
        query = f"authors~{versions}"
        LOGGER.info(f"query: {query}")
        return query

    def get_s3_client(self) -> S3Client:
        s3_client = S3Client(
            bucket=self.args.s3_bucket_url,
            access_key=os.environ["MOBSTER_S3_ACCESS_KEY"],
            secret_key=os.environ["MOBSTER_S3_SECRET_KEY"],
            concurrency_limit=self.args.concurrency,
        )
        return s3_client

    async def gather_s3_input_data(self, rid: ReleaseId) -> tuple[Path, Path]:
        LOGGER.debug(f"gathering input data for release_id: '{rid}'")
        path_snapshot = (
            self.args.output_path / S3Client.snapshot_prefix / f"{rid}.snapshot.json"
        )
        path_release_data = (
            self.args.output_path
            / S3Client.release_data_prefix
            / f"{rid}.release_data.json"
        )
        await self.s3_client.get_snapshot(path_snapshot, rid)
        await self.s3_client.get_release_data(path_release_data, rid)
        LOGGER.info(f"input data gathered from S3 bucket, for release_id: {rid}")
        return path_snapshot, path_release_data

    async def process_sboms(
        self, release_id: str, path_release_data: Path, path_snapshot: Path
    ):
        if self.sbom_type == SbomType.PRODUCT:
            await process_product_sboms(
                ProcessProductArgs(
                    release_data=path_release_data,
                    concurrency=self.args.concurrency,
                    data_dir=self.args.output_path,
                    snapshot_spec=path_snapshot,
                    atlas_api_url=self.args.tpa_base_url,
                    retry_s3_bucket=self.args.s3_bucket_url,
                    release_id=ReleaseId(release_id),
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
                    release_id=ReleaseId(release_id),
                    labels={},
                    augment_concurrency=self.args.concurrency,
                    result_dir=self.args.output_path,
                    tpa_retries=self.args.tpa_retries,
                    upload_concurrency=self.args.concurrency,
                )
            )


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
