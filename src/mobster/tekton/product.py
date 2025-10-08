"""
Script used in Tekton task for processing product SBOMs.
"""

import argparse as ap
import asyncio
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from mobster.log import setup_logging
from mobster.release import ReleaseId
from mobster.tekton.artifact import get_product_artifact
from mobster.tekton.common import (
    CommonArgs,
    add_common_args,
    connect_with_s3,
    get_atlas_upload_config,
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
        sbom_path: Path where the generated product SBOM should be stored. If
            it's equal to None, a temporary file will be used instead.
    """

    release_data: Path
    concurrency: int
    sbom_path: Path | None


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
    parser.add_argument(
        "--sbom-path",
        type=Path,
        help="Optional path specifying where the generated product SBOM "
        "should be stored. If not provided, a temporary file will be used "
        "and deleted at the end of the program."
        "Should only be specified for integration testing purposes.",
    )
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
        atlas_retries=args.atlas_retries,
        skip_upload=args.skip_upload,
        sbom_path=args.sbom_path,
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
    s3 = connect_with_s3(args.retry_s3_bucket)

    if not args.skip_upload and s3:
        LOGGER.info(
            "Uploading snapshot and release data to S3 with release_id=%s",
            args.release_id,
        )
        await upload_snapshot(s3, args.snapshot_spec, args.release_id)
        await upload_release_data(s3, args.release_data, args.release_id)
    else:
        LOGGER.debug(
            "skip_upload=%s, so no snapshot / "
            "release data upload to S3, for release_id=%s",
            args.skip_upload,
            args.release_id,
        )

    if args.sbom_path is None:
        sbom_path = Path(
            tempfile.NamedTemporaryFile(suffix=".json").name  # pylint: disable=consider-using-with
        )
    else:
        sbom_path = args.sbom_path

    create_product_sbom(
        sbom_path,
        args.snapshot_spec,
        args.release_data,
        args.release_id,
        args.concurrency,
    )

    if args.skip_upload:
        LOGGER.debug(
            "skip_upload=%s, no upload to TPA for release_id=%s",
            args.skip_upload,
            args.release_id,
        )
    else:
        report = await upload_sboms(
            get_atlas_upload_config(
                base_url=args.atlas_api_url,
                retries=args.atlas_retries,
                workers=args.upload_concurrency,
                labels=args.labels,
            ),
            s3,
            paths=[sbom_path],
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
