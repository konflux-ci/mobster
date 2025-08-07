"""
Script used in Tekton task for processing product SBOMs.
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
    upload_release_data,
    upload_sboms,
    upload_snapshot,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class ProcessProductArgs(CommonArgs):
    """
    Arguments for product SBOM processing.

    Attributes:
        release_data: Path to release data file.
    """

    release_data: Path


def parse_args() -> ProcessProductArgs:
    """
    Parse command line arguments for product SBOM processing.

    Returns:
        ProcessProductArgs: Parsed arguments.
    """
    parser = ap.ArgumentParser()
    add_common_args(parser)
    parser.add_argument("--release-data", type=Path, required=True)
    args = parser.parse_args()

    # the snapshot_spec and release_data are joined with the data_dir as
    # previous tasks provide the paths as relative to the dataDir
    return ProcessProductArgs(
        data_dir=args.data_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        release_data=args.data_dir / args.release_data,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
        print_digests=args.print_digests,
        concurrency=args.concurrency,
    )  # pylint:disable=duplicate-code


def create_product_sbom(
    sbom_path: Path,
    snapshot_spec: Path,
    release_data: Path,
    release_id: ReleaseId,
    concurrency: int,
) -> None:
    """
    Create a product SBOM using the mobster generate command.

    Args:
        sbom_path: Path where the SBOM will be saved.
        snapshot_spec: Path to snapshot specification file.
        release_data: Path to release data file.
        release_id: Release ID to store in SBOM file.
    """
    cmd = [
        "mobster",
        "--verbose",
        "generate",
        "--output",
        str(sbom_path),
        "product",
        "--snapshot",
        str(snapshot_spec),
        "--release-data",
        str(release_data),
        "--release-id",
        str(release_id),
        "--concurrency",
        str(concurrency),
    ]

    subprocess.run(cmd, check=True)


async def process_product_sboms(args: ProcessProductArgs) -> None:
    """
    Process product SBOMs by creating and uploading them.

    Args:
        args: Arguments containing data directory and configuration.
    """
    sbom_dir = args.data_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)
    sbom_path = sbom_dir / "sbom.json"
    s3 = connect_with_s3(args.retry_s3_bucket)

    if s3:
        LOGGER.info(
            "Uploading snapshot and release data to S3 with release_id=%s",
            args.release_id,
        )
        await upload_snapshot(s3, args.snapshot_spec, args.release_id)
        await upload_release_data(s3, args.release_data, args.release_id)

    create_product_sbom(
        sbom_path,
        args.snapshot_spec,
        args.release_data,
        args.release_id,
        args.concurrency,
    )
    if args.print_digests:
        await print_digests([sbom_path])

    await upload_sboms(sbom_dir, args.atlas_api_url, s3)


def main() -> None:
    """
    Main entry point for product SBOM processing.
    """
    setup_logging(verbose=True)
    args = parse_args()
    asyncio.run(process_product_sboms(args))
