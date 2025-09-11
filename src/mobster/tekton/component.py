"""
Script used for processing component SBOMs in Tekton task.
"""

import argparse as ap
import asyncio
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mobster.log import setup_logging
from mobster.release import ReleaseId
from mobster.tekton.common import (
    CommonArgs,
    add_common_args,
    connect_with_s3,
    print_digests,
    upload_sboms,
    upload_snapshot,
)
from mobster.tekton.report import ComponentReport, write_report

LOGGER = logging.getLogger(__name__)


@dataclass
class ProcessComponentArgs(CommonArgs):
    """
    Arguments for component SBOM processing.

    Attributes:
        augment_concurrency: maximum number of concurrent SBOM augmentation operations
        upload_concurrency: maximum number of concurrent SBOM upload operations
    """

    augment_concurrency: int
    upload_concurrency: int


def parse_args() -> ProcessComponentArgs:
    """
    Parse command line arguments for component SBOM processing.

    Returns:
        ProcessComponentArgs: Parsed arguments.
    """
    parser = ap.ArgumentParser()
    add_common_args(parser)
    parser.add_argument("--augment-concurrency", type=int, default=8)
    parser.add_argument("--upload-concurrency", type=int, default=8)
    args = parser.parse_args()

    # the snapshot_spec is joined with the data_dir as previous tasks provide
    # the path as relative to the dataDir
    return ProcessComponentArgs(
        data_dir=args.data_dir,
        result_dir=args.data_dir / args.result_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
        print_digests=args.print_digests,
        augment_concurrency=args.augment_concurrency,
        upload_concurrency=args.upload_concurrency,
        labels=args.labels,
    )


def augment_component_sboms(
    sbom_path: Path, snapshot_spec: Path, release_id: ReleaseId, concurrency: int
) -> None:
    """
    Augment component SBOMs using the mobster augment command.

    Args:
        sbom_path: Path where the SBOM will be saved.
        snapshot_spec: Path to snapshot specification file.
        release_id: Release ID to store in SBOM file.
        concurrency: Maximum number of concurrent augmentation operations.
    """
    cmd = [
        "mobster",
        "--verbose",
        "augment",
        "--output",
        str(sbom_path),
        "oci-image",
        "--snapshot",
        str(snapshot_spec),
        "--release-id",
        str(release_id),
        "--concurrency",
        str(concurrency),
    ]  # pylint: disable=duplicate-code

    subprocess.run(cmd, check=True)


async def process_component_sboms(args: ProcessComponentArgs) -> None:
    """
    Process component SBOMs by augmenting and uploading them.

    Args:
        args: Arguments containing data directory and configuration.
    """
    sbom_dir = args.data_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)
    s3 = connect_with_s3(args.retry_s3_bucket)

    if s3:
        LOGGER.info("Uploading snapshot to S3 with release_id=%s", args.release_id)
        await upload_snapshot(s3, args.snapshot_spec, args.release_id)

    LOGGER.info("Starting SBOM augmentation")
    augment_component_sboms(
        sbom_dir, args.snapshot_spec, args.release_id, args.augment_concurrency
    )
    if args.print_digests:
        await print_digests(list(sbom_dir.iterdir()))

    report = await upload_sboms(
        sbom_dir, args.atlas_api_url, s3, args.upload_concurrency, args.labels
    )
    component_report = ComponentReport(mobster_component_report=report)
    write_report(component_report, args.result_dir)


def main() -> None:
    """
    Main entry point for component SBOM processing.
    """
    setup_logging(verbose=True)
    args = parse_args()
    asyncio.run(process_component_sboms(args))
