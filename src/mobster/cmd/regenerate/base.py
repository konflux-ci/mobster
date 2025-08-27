"""A command execution module for regenerating SBOM documents."""

import json
import logging
import os
from abc import ABC
from typing import Any

import spdx_tools.spdx.writer.json.json_writer as spdx_json_writer

from mobster import utils
from mobster.cmd.base import Command
from mobster.cmd.download.download_tpa import get_tpa_default_client
from mobster.cmd.generate.product import create_sbom, parse_release_notes
from mobster.cmd.upload.model import SbomSummary
from mobster.cmd.upload.tpa import TPAClient
from mobster.release import ReleaseId
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


class RegenerateCommand(Command, ABC):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.tpa_base_url: str | None = None
        self.s3_bucket_url: str | None = None
        self.mobster_versions: str | None = None
        self.component_purl: str | None = None
        self.concurrency: int | None = None
        self.output: str
        self.dry_run: bool = False
        self.tpa_base_url: str | None = None
        self.tpa_client: TPAClient | None = None
        self.s3_client: S3Client | None = None
        # accounting
        self.count_sboms_success: int = 0
        self.count_sboms_failed: int = 0
        self.exit_code = 1

    async def save(self) -> None:
        """
        Save the command's state.
        """

    async def regenerate_sboms_set(self) -> None:
        """
        regenerate the set of sboms indicated by the cli args
        """
        LOGGER.info("Searching for matching product-level SBOMs..")

        # query for relevant sboms, based on the CLI-provided mobster versions
        sboms = self.tpa_client.list_sboms(query=self.construct_query(),
                                           sort="ingested")

        LOGGER.info("Regenerating product-level SBOMs..")

        async for sbom in sboms:
            if await self.regenerate_sbom(sbom):
                self.count_sboms_success += 1
            else:
                self.count_sboms_failed += 1

        LOGGER.info(f"Successfully regenerated {self.count_sboms_success} of "
                    f"{self.count_sboms_success + self.count_sboms_failed} "
                    f"product-level SBOMs.")
        LOGGER.info(f"Failed to regenerate {self.count_sboms_failed} of "
                    f"{self.count_sboms_success + self.count_sboms_failed} "
                    f"product-level SBOMs.")

    async def regenerate_sbom(self, sbom_sum: SbomSummary) -> bool:
        """
        regenerate the given sbom (re-create it, upload it, then delete old version)
        """
        # ensure sbom name is a valid filename
        name = utils.normalize_file_name(sbom_sum.name)
        local_path_original = self.output / f"{name}.original.json"
        local_path_regenerated = self.output / f"{name}.regenerated.json"
        # download sbom
        LOGGER.info(f"downloading SBOM: {sbom_sum.id} to: {local_path_original}")
        await self.tpa_client.download_sbom(sbom_sum.id, local_path_original)
        try:
            with open(local_path_original) as f:
                sbom = json.load(f)
        except FileNotFoundError:
            LOGGER.error(f"'{local_path_original}' not found.")
            return False
        except json.JSONDecodeError:
            LOGGER.error("Error: Invalid JSON in '{local_path_original}'.")
            return False
        # check for package, if applicable
        if (self.component_purl and
                not self.contains_package_ref(sbom, self.component_purl)):
            LOGGER.info(f"purl: {self.component_purl} not in SBOM: {sbom_sum.id}")
            return False
        # re-create
        release_id = self.extract_release_id(sbom)
        if not release_id:
            LOGGER.info(f"No release_id in SBOM: {sbom_sum.id} ({sbom_sum.name})")
            return False
        # gather related data from s3 bucket
        path_snapshot, path_release_data = await self.gather_s3_input_data(release_id)
        if not path_snapshot:
            LOGGER.info(f"No S3 snapshot found for {sbom_sum.id} ({sbom_sum.name})")
            return False
        LOGGER.info(f"proceeding to regenerate SBOM: {sbom_sum.id}  ({sbom_sum.name})")
        release_notes = parse_release_notes(path_release_data)
        document = create_sbom(release_notes, path_snapshot, release_id)
        # write to file
        with open(local_path_regenerated, "w", encoding="utf-8") as stream:
            spdx_json_writer.write_document_to_stream(
                document=document, stream=stream, validate=True
            )
        if self.dry_run:
            LOGGER.info(f"*Dry Run 'upload' regenerated SBOM: "
                        f"{sbom_sum.id} ({sbom_sum.name})")
            LOGGER.info(f"*Dry Run 'delete' original SBOM: "
                        f"{sbom_sum.id} ({sbom_sum.name})")
            return False
        # upload
        response_upload = await self.tpa_client.upload_sbom(local_path_regenerated)
        # check upload status
        if response_upload.status_code != 200:
            # upload failed, log and abort regeneration for this SBOM
            LOGGER.error(f"upload SBOM failed with status: "
                         f"{response_upload.status_code}, for SBOM: {name}, "
                         f"with message: {response_upload.text}")
            return False
        LOGGER.info(f"Success: uploaded regen SBOM: {sbom_sum.id} ({sbom_sum.name})")
        # delete
        response_delete = await self.tpa_client.delete(sbom_sum.id)
        # check delete status
        if response_delete.status_code != 200:
            # delete failed, log and abort regeneration for this SBOM
            LOGGER.error(f"delete SBOM failed for SBOM: {sbom_sum.id}, "
                         f"status: {response_upload.status_code}, "
                         f"message: {response_upload.text}")
            return False
        LOGGER.info(f"Success: deleted original SBOM: {sbom_sum.id} ({sbom_sum.name})")
        return True

    @staticmethod
    def extract_release_id(sbom: SbomSummary):
        if "annotations" in sbom:
            for annotation in sbom["annotations"]:
                if "release_id=" in annotation["comment"]:
                    return annotation["comment"].partition("release_id=")[2]
        # no release_id found
        LOGGER.info("no release_id found in SBOM")
        return None

    @staticmethod
    def contains_package_ref(self, sbom: SbomSummary, purl: str) -> bool:
        if "packages" in sbom:
            for package in sbom["packages"]:
                if "externalRefs" in package:
                    for externalRef in package["externalRefs"]:
                        if externalRef["referenceType"] == "purl" and \
                                externalRef["referenceLocator"] == purl:
                            return True
        # no matching package ref found
        return False

    def get_s3_client(self) -> S3Client:
        s3_client = S3Client(
            bucket=self.s3_bucket_url,
            access_key=os.environ["MOBSTER_S3_ACCESS_KEY"],
            secret_key=os.environ["MOBSTER_S3_SECRET_KEY"],
            concurrency_limit=self.concurrency
        )
        return s3_client

    async def gather_s3_input_data(self, release_id: ReleaseId) \
            -> tuple[str, str] | None:
        if self.s3_client.snapshot_exists(release_id) and \
                self.s3_client.release_data_exists(release_id):
            path_snapshot = self.output / f"{release_id.id}.snapshot.json"
            path_release_data = self.output / f"{release_id.id}.release_data.json"
            await self.s3_client.get_snapshot(release_id)
            await self.s3_client.get_release_data(release_id)
            LOGGER.info(f"input data gathered from S3 bucket, "
                        f"for release_id: {release_id}")
            return path_snapshot, path_release_data
        LOGGER.error(f"no input data found in S3 bucket, for release_id: {release_id}")
        return None

    def construct_query(self):
        versions = "|".join(f"Tool: Mobster-{str(v).strip()}"
                            for v in self.mobster_versions.split(","))
        query = f"authors~{versions}"
        LOGGER.info(f"query: {query}")
        return query

    def init(self):
        self.setup_cli_args()
        if not self.validate_cli_args():
            self.exit_code = 1
            return
        self.setup_clents()
        self.print_runtime_config()

    def setup_cli_args(self) -> None:
        self.tpa_base_url = self.cli_args.tpa_base_url
        self.mobster_versions = self.cli_args.mobster_versions
        if "component_purl" in self.cli_args:
            self.component_purl = self.cli_args.component_purl
        self.s3_bucket_url = self.cli_args.s3_bucket_url
        self.concurrency = self.cli_args.concurrency
        self.output = self.cli_args.output
        self.dry_run = self.cli_args.dry_run

    def validate_cli_args(self) -> bool:
        # ensure at least some mobster version is specified
        if not self.cli_args.mobster_versions:
            LOGGER.error("--mobster-versions cannot be empty")
            return False
        return True

    def setup_clents(self) -> None:
        self.tpa_client = get_tpa_default_client(self.tpa_base_url)
        self.s3_client = self.get_s3_client()

    def print_runtime_config(self) -> None:
        print(f"tpa_base_url: {self.tpa_base_url}")
        print(f"mobster_versions: {self.mobster_versions}")
        print(f"s3_bucket_url: {self.s3_bucket_url}")
        print(f"concurrency: {self.concurrency}")
        print(f"output: {self.output}")
        print(f"dry_run: {self.dry_run}")
