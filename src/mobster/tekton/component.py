"""
Script used for processing component SBOMs in Tekton task.
"""

import asyncio
import logging
import tempfile
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar

from mobster.cmd.augment.bom import AugmentConfig, BOMAugmenter, BOMRefDetail
from mobster.cmd.generate.product import parse_release_notes
from mobster.oci import cosign
from mobster.release import ReleaseId, make_snapshot
from mobster.tekton.artifact import (
    get_component_artifact,
)
from mobster.tekton.common import (
    CommonArgs,
    add_common_args,
    connect_with_s3,
    get_atlas_upload_config,
    upload_sboms,
    upload_snapshot,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class ProcessComponentArgs(CommonArgs):
    """
    Arguments for component SBOM processing.

    Attributes:
        augment_concurrency: maximum number of concurrent SBOM augmentation operations
        cosign_verify_config: config for cosign verification
        release_data: release data FS path
    """

    augment_concurrency: int
    cosign_verify_config: cosign.VerifyConfig
    release_data: Path


def parse_component_args(cli_args: Sequence[str] | None = None) -> ProcessComponentArgs:
    """
    Parse command line arguments for component SBOM processing.

    Returns:
        ProcessComponentArgs: Parsed arguments.
    """
    parser = ArgumentParser()
    add_common_args(parser)
    add_component_args(parser)

    args = parser.parse_args(args=cli_args)

    # pylint: disable=duplicate-code
    keyless_verify_config = None
    if args.oidc_identity_pattern and args.oidc_issuer:
        keyless_verify_config = cosign.KeylessVerifyConfig(
            identity_pattern=args.oidc_identity_pattern, oidc_issuer=args.oidc_issuer
        )
    verify_config = cosign.VerifyConfig(
        static_verify_key=args.verify_key,
        keyless_verify_config=keyless_verify_config,
    )

    # the snapshot_spec is joined with the data_dir as previous tasks provide
    # the path as relative to the dataDir
    return ProcessComponentArgs(
        data_dir=args.data_dir,
        result_dir=args.data_dir / args.result_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        release_data=args.data_dir / args.release_data,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
        augment_concurrency=args.augment_concurrency,
        upload_concurrency=args.upload_concurrency,
        labels=args.labels,
        atlas_retries=args.atlas_retries,
        skip_upload=args.skip_upload,
        skip_s3_upload=False,
        cosign_verify_config=verify_config,
    )
    # pylint: enable=duplicate-code


def add_component_args(parser: ArgumentParser) -> None:
    """
    Add args common to all component commands.
    """
    parser.add_argument("--augment-concurrency", type=int, default=8)
    parser.add_argument("--upload-concurrency", type=int, default=8)
    parser.add_argument(
        "--release-data",
        type=Path,
        help="path to the merged data file in JSON format",
        required=True,
    )
    parser.add_argument(
        "--rekor-url", type=str, help="The URL of the Rekor server", default=None
    )
    parser.add_argument(
        "--verify-key",
        type=str,
        help="The cosign verification key for attest downloading and verification.",
        default=None,
    )
    parser.add_argument("--fulcio-url", type=str, help="URL of the Fulcio server")
    parser.add_argument(
        "--oidc-issuer",
        type=str,
        help="OIDC issuer URL for attestation verification",
        default=None,
    )
    parser.add_argument(
        "--oidc-identity-pattern",
        type=str,
        help="OIDC identity pattern for attestation verification",
        default=None,
    )


def get_cpes_from_release_data(release_data: Path) -> list[str]:
    """
    Get CPE information from release_data

    Args:
        release_data: Path to release data file
    Returns:
        list[str]: List of string CPEs contained in the release_data
    """
    release_notes = parse_release_notes(release_data)
    if release_notes is None:
        return []
    return (
        release_notes.cpe
        if isinstance(release_notes.cpe, list)
        else [release_notes.cpe]
    )


ConfigT = TypeVar("ConfigT", bound="ProcessComponentArgs")


class ComponentBOMHandler(ABC, Generic[ConfigT]):
    """
    Abstract class for e2e *BOM component handling.
    Must be subclassed.

    Attributes:
        augmenter_class:
            The augmenter used for fetching and augmenting
            the specific *BOM type.
    """

    augmenter_class: type[BOMAugmenter]

    async def augment_component_boms(
        # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        sbom_path: Path,
        snapshot_spec: Path,
        release_id: ReleaseId,
        cosign_client: cosign.SupportsFetch,
        augment_concurrency: int,
        release_data: Path,
    ) -> list[BOMRefDetail | None]:
        """
        Augment component SBOMs using the mobster augment command.

        Args:
            sbom_path: Path where the SBOM will be saved.
            snapshot_spec: Path to snapshot specification file.
            release_id: Release ID to store in SBOM file.
            cosign_client: Cosign fetch client.
            augment_concurrency: Maximum number of concurrent augmentation operations.
            release_data: Path to release data file
        """
        semaphore = asyncio.Semaphore(augment_concurrency)
        snapshot = await make_snapshot(snapshot_spec, None, semaphore)
        config = AugmentConfig(
            cosign=cosign_client,
            verify=True,
            semaphore=semaphore,
            output_dir=sbom_path,
            release_id=release_id,
            cpes=get_cpes_from_release_data(release_data),
        )

        result_details = await self.augmenter_class().augment_boms(config, snapshot)
        LOGGER.debug("Successfully augmented SBOMs for ReleaseId: %s", str(release_id))
        return result_details

    def assess_results(self, results: list[BOMRefDetail | None]) -> list[BOMRefDetail]:
        """
        Determines how each handler responds to failures.
        Args:
            results: The results of augmentation.

        Returns:
            Cleaned up results (failures are removed).
        """
        return [result for result in results if result is not None]

    async def process_component_boms(self, args: ConfigT) -> None:
        """
        Process component SBOMs by augmenting and uploading them.

        Args:
            args: Arguments containing data directory and configuration.
        """
        s3 = connect_with_s3(args.retry_s3_bucket)

        if (not args.skip_s3_upload) and (not args.skip_upload) and s3:
            LOGGER.info("Uploading snapshot to S3 with release_id=%s", args.release_id)
            await upload_snapshot(s3, args.snapshot_spec, args.release_id)
        else:
            LOGGER.debug(
                "skip_upload=%s, so no snapshot / "
                "release data upload to S3, for release_id=%s",
                args.skip_upload,
                args.release_id,
            )

        LOGGER.info("Starting SBOM augmentation")

        with tempfile.TemporaryDirectory() as sbom_dir:
            results = await self.augment_component_boms(
                Path(sbom_dir),
                args.snapshot_spec,
                args.release_id,
                cosign.get_cosign_fetcher(args.cosign_verify_config),
                args.augment_concurrency,
                args.release_data,
            )
            cleaned_results = self.assess_results(results)

            if args.skip_upload:
                LOGGER.debug(
                    "skip_upload=%s, so no upload to TPA or registry,"
                    " for release_id=%s",
                    args.skip_upload,
                    args.release_id,
                )
            else:
                # Both attest and upload SBOMs
                await self.attest_boms(args, cleaned_results)
                atlas_config = get_atlas_upload_config(
                    base_url=args.atlas_api_url,
                    retries=args.atlas_retries,
                    workers=args.upload_concurrency,
                    labels=args.labels,
                )

                report = await upload_sboms(
                    atlas_config, s3, list(Path(sbom_dir).iterdir())
                )

                artifact = get_component_artifact(report)
                artifact.write_result(args.result_dir)

    @staticmethod
    @abstractmethod
    async def attest_boms(args: ConfigT, results: list[BOMRefDetail]) -> None:
        """
        Abstract method for attesting SBOMs
        Args:
            args: Configuration for the BOM handling.
            results: Augmentation results for attesting.
        """
