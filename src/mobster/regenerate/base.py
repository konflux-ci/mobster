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
        verbose: Run in verbose mode (additional logs/trace)
        sbom_type: SBOMType (Product/Component) used for this regenerator
    """

    output_path: str
    tpa_base_url: str | None = None
    s3_bucket_url: str | None = None
    mobster_versions: str | None = None
    concurrency: int | None = None
    tpa_retries: int = 1
    dry_run: bool = False
    verbose: bool = False
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
        LOGGER.info("Searching for matching product-level SBOMs..")

        self.tpa_client = get_tpa_default_client(self.args.tpa_base_url)
        self.s3_client = self.get_s3_client()

        # query for relevant sboms, based on the CLI-provided mobster versions
        sboms = self.tpa_client.list_sboms(
            query=self.construct_query(), sort="ingested"
        )

        count_sboms_success = 0

        LOGGER.info(f"Regenerating {self.sbom_type.value} SBOMs..")

        async for sbom in sboms:
            LOGGER.info(
                f"Regenerating {self.sbom_type.value} SBOM: {sbom.id} ({sbom.name})"
            )
            try:
                await self.regenerate_sbom(sbom)
                count_sboms_success += 1
            except SBOMError as e:
                LOGGER.error(e)
                exit(1)

        LOGGER.info(
            f"Successfully regenerated {count_sboms_success}"
            f" {self.sbom_type.value} SBOMs."
        )

    async def regenerate_sbom(self, sbom: SbomSummary) -> None:
        """
        regenerate the given sbom (re-create it, upload it, then delete old version)
        """
        release_id = await self.get_release_id(sbom)
        # gather related data from s3 bucket
        path_snapshot, path_release_data = await self.gather_s3_input_data(release_id)
        LOGGER.info(f"proceeding to regenerate SBOM: {sbom.id}  ({sbom.name})")
        if self.args.dry_run:
            LOGGER.info(f"*Dry Run recreate SBOM: {sbom.id} ({sbom.name})")
            return
        else:
            await self.process_sboms(release_id.id, path_release_data, path_snapshot)

        if self.args.dry_run:
            LOGGER.info(f"*Dry Run 'delete' original SBOM: {sbom.id} ({sbom.name})")
            return
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
            LOGGER.debug(f"No release_id in SBOM Summary: {sbom.id} ({sbom.name})")
            # LOGGER.debug(f"{sbom}")
            # download the complete SBOM and extract the release_id
            release_id = await self.download_and_extract_release_id(sbom)
            if not release_id:
                raise SBOMError(
                    f"No release_id found for SBOM: {sbom.id} ({sbom.name})"
                )
        return release_id

    def extract_release_id(self, sbom: SbomSummary) -> ReleaseId | None:
        if self.sbom_type == SbomType.PRODUCT and "annotations" in sbom:
            for annot in sbom["annotations"]:
                if "release_id=" in annot["comment"]:
                    return ReleaseId(annot["comment"].partition("release_id=")[2])
        elif self.sbom_type == SbomType.COMPONENT and "properties" in sbom:
            for prop in sbom["properties"]:
                if prop["name"] == "release_id":
                    return prop["value"]
        # no release_id found
        LOGGER.info("no release_id found in SBOM")
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

    async def gather_s3_input_data(self, release_id: ReleaseId) -> tuple[Path, Path]:
        if await self.s3_client.snapshot_exists(
            release_id
        ) and await self.s3_client.release_data_exists(release_id):
            path_snapshot = Path(
                f"{self.args.output_path}/{release_id.id}.snapshot.json"
            )
            path_release_data = Path(
                f"{self.args.output_path}/{release_id.id}.release_data.json"
            )
            if not await self.s3_client.get_snapshot(path_snapshot, release_id):
                raise SBOMError(f"missing S3 snapshot, for release_id: {release_id}")
            if not await self.s3_client.get_release_data(path_release_data, release_id):
                raise SBOMError(f"missing S3 ReleaseData, for release_id: {release_id}")
            LOGGER.info(
                f"input data gathered from S3 bucket, for release_id: {release_id}"
            )
            return path_snapshot, path_release_data
        raise SBOMError(f"no data found in S3 bucket, for release_id: {release_id}")

    async def process_sboms(
        self, release_id: str, path_release_data: Path, path_snapshot: Path
    ):
        if self.sbom_type == SbomType.PRODUCT:
            await process_product_sboms(
                ProcessProductArgs(
                    release_data=path_release_data,
                    concurrency=self.args.concurrency,
                    data_dir=Path(self.args.output_path),
                    snapshot_spec=path_snapshot,
                    atlas_api_url=self.args.tpa_base_url,
                    retry_s3_bucket=self.args.s3_bucket_url,
                    release_id=ReleaseId(release_id),
                    labels={},
                    result_dir=Path(self.args.output_path),
                    tpa_retries=self.args.tpa_retries,
                    upload_concurrency=self.args.concurrency,
                )
            )
            #  release_notes, snapshot, release_id
        elif self.sbom_type == SbomType.COMPONENT:
            await process_component_sboms(
                ProcessComponentArgs(
                    data_dir=Path(self.args.output_path),
                    snapshot_spec=path_snapshot,
                    atlas_api_url=self.args.tpa_base_url,
                    retry_s3_bucket=self.args.s3_bucket_url,
                    release_id=ReleaseId(release_id),
                    labels={},
                    augment_concurrency=self.args.concurrency,
                    result_dir=Path(self.args.output_path),
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

    return RegenerateArgs(
        output_path=args.output_path,
        tpa_base_url=args.tpa_base_url,
        s3_bucket_url=args.s3_bucket_url,
        mobster_versions=args.mobster_versions,
        concurrency=args.concurrency,
        dry_run=args.dry_run,
    )  # pylint:disable=duplicate-code


def add_args(parser: ArgumentParser) -> None:
    """
    Add command line arguments to the parser.

    Args:
        parser: argument parser to add commands to
    """
    parser.add_argument(
        "--tpa-base-url",
        type=str,
        required=True,
        help="URL of the TPA server",
    )

    parser.add_argument(
        "--mobster-versions",
        type=str,
        required=True,
        help="Comma separated list of mobster versions to query for, "
        "e.g.:  0.2.1,0.5.0",
    )

    parser.add_argument(
        "--s3-bucket-url",
        type=str,
        required=True,
        help="AWS S3 bucket URL",
    )

    parser.add_argument(
        "--concurrency",
        type=parse_concurrency,
        default=8,
        help="concurrency limit for S3 client (non-zero integer)",
    )

    parser.add_argument(
        "--output-path",
        type=Path,
        help="Path to the output file. If not provided, the output will be printed"
        "to stdout.",
    )

    parser.add_argument(
        "--dry-run",
        type=bool,
        default=False,
        help="Run in 'dry run' only mode (skips destructive TPA IO)",
    )

    parser.add_argument(
        "--verbose",
        type=bool,
        default=False,
        help="Run in verbose mode (additional logs/trace)",
    )

    parser.add_argument(
        "--tpa-retries",
        type=int,
        default=1,
        help="total number of attempts for TPA requests",
    )
