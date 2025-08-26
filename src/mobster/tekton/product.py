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
from mobster.tekton.artifact import get_product_artifact
from mobster.tekton.common import (
    CommonArgs,
    add_common_args,
    connect_with_s3,
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
        concurrency: maximum number of concurrent operations
    """

    release_data: Path
    concurrency: int


def parse_args() -> ProcessProductArgs:
    """
    Parse command line arguments for product SBOM processing.

    Returns:
        ProcessProductArgs: Parsed arguments.
    """
    parser = ap.ArgumentParser()
    add_common_args(parser)
    parser.add_argument("--release-data", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()

    # the snapshot_spec and release_data are joined with the data_dir as
    # previous tasks provide the paths as relative to the dataDir
    return ProcessProductArgs(
        data_dir=args.data_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        release_data=args.data_dir / args.release_data,
        result_dir=args.data_dir / args.result_dir,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
        upload_concurrency=args.concurrency,
        concurrency=args.concurrency,
        labels=args.labels,
        tpa_retries=args.tpa_retries,
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
        concurrency: Maximum number of concurrent operations.
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
    sbom_path = args.ensured_sbom_dir() / "sbom.json"
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

    report = await upload_sboms(
        args.to_upload_config(),
        s3,
    )
    artifact = get_product_artifact(report)
    artifact.write_result(args.result_dir)


def main() -> None:
    """
    Main entry point for product SBOM processing.
    """
    setup_logging(verbose=True)
    args = parse_args()
    asyncio.run(process_product_sboms(args))
