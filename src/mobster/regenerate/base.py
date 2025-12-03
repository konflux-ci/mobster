"""A command execution module for regenerating SBOM documents."""

import asyncio
import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from subprocess import CalledProcessError

from mobster.error import SBOMError
from mobster.oci.cosign import CosignConfig
from mobster.release import ReleaseId
from mobster.tekton.component import ProcessComponentArgs, process_component_sboms
from mobster.tekton.product import ProcessProductArgs, process_product_sboms
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)

""" directory prefix for (re)generated SBOMs """
GENERATED_SBOMS_PREFIX = "sbom"


class SBOMType(Enum):
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
class CommonArgs:
    """
    Common regeneration arguments.

    Attributes:
        tpa_base_url: path to snapshot spec file
        tpa_retries: total number of attempts for TPA requests
        output_path: Path to the output files.
        s3_bucket_url: url of the TPA instance to use
        concurrency: concurrency limit for S3 client (non-zero integer)
        dry_run: Run in 'dry run' only mode (skips destructive TPA IO)
        fail_fast: fail and exit on first regen error (default: True)
        verbose: Run in verbose mode (additional logs/trace)
    """

    # pylint: disable=too-many-instance-attributes
    tpa_base_url: str
    tpa_retries: int
    output_path: Path
    s3_bucket_url: str
    concurrency: int
    dry_run: bool
    fail_fast: bool
    verbose: bool


class SBOMRegenerator(ABC):
    """base regenerator class for SBM regeneration"""

    def __init__(
        self,
        args: CommonArgs,
        sbom_type: SBOMType,
    ) -> None:
        self.args = args
        self.sbom_type = sbom_type
        self.semaphore = asyncio.Semaphore(self.args.concurrency)
        self.s3_client = self.setup_s3_client()
        self.sbom_release_groups: set[ReleaseId] = set()

    @abstractmethod
    async def populate_releases(self) -> None:
        """
        Populate release IDs according to the mechanism.
        Returns: Nothing
        """

    async def regenerate_sboms(self) -> None:
        """
        Regenerate the SBOMs of the releases. Requires the
        attribute `sbom_release_groups` to be set.
        Returns: Nothing
        """
        await self.populate_releases()
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

    async def regenerate_release_groups(self) -> None:
        """walk the set of release groups, and regenerate each release"""
        LOGGER.info("Regenerating %s release groups..", self.sbom_type.value)
        regen_tasks = []
        for release_id in self.sbom_release_groups:
            regen_tasks.append(self.regenerate_sbom_release(release_id))
        results = await asyncio.gather(*regen_tasks)
        failed_releases = []
        for release_id, result in zip(self.sbom_release_groups, results, strict=False):
            if not result:
                failed_releases.append(release_id)
        LOGGER.warning("Failed releases: %s", failed_releases)
        LOGGER.info("Finished regenerating %s release groups.", self.sbom_type.value)

    async def regenerate_sbom_release(self, release_id: ReleaseId) -> bool:
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
            return True
        except SBOMError as e:
            if self.args.fail_fast:
                raise e
            LOGGER.warning(str(e))
            return False

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
        bucket_name, endpoint_url = self.parse_s3_bucket_url(self.args.s3_bucket_url)
        # Used by default client later in the script for retrying
        os.environ["AWS_ENDPOINT_URL"] = endpoint_url
        try:
            if self.sbom_type == SBOMType.PRODUCT:
                await process_product_sboms(
                    ProcessProductArgs(
                        release_data=path_release_data,
                        concurrency=self.args.concurrency,
                        data_dir=self.args.output_path,
                        snapshot_spec=path_snapshot,
                        atlas_api_url=self.args.tpa_base_url,
                        retry_s3_bucket=bucket_name,
                        release_id=release_id,
                        labels={},
                        result_dir=self.args.output_path,
                        sbom_path=self.args.output_path
                        / GENERATED_SBOMS_PREFIX
                        / f"{str(release_id)}.json",
                        atlas_retries=self.args.tpa_retries,
                        upload_concurrency=self.args.concurrency,
                        skip_upload=self.args.dry_run,
                        skip_s3_upload=True,
                    )
                )
                #  release_notes, snapshot, release_id
            elif self.sbom_type == SBOMType.COMPONENT:
                await process_component_sboms(
                    ProcessComponentArgs(
                        data_dir=self.args.output_path,
                        snapshot_spec=path_snapshot,
                        atlas_api_url=self.args.tpa_base_url,
                        retry_s3_bucket=bucket_name,
                        release_id=release_id,
                        labels={},
                        augment_concurrency=self.args.concurrency,
                        result_dir=self.args.output_path,
                        atlas_retries=self.args.tpa_retries,
                        upload_concurrency=self.args.concurrency,
                        attestation_concurrency=self.args.concurrency,
                        skip_upload=self.args.dry_run,
                        cosign_config=CosignConfig(),
                        skip_s3_upload=True,
                    )
                )
        except CalledProcessError as e:
            raise SBOMError from e
