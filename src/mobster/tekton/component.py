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
from mobster.tekton.common import (
    CommonArgs,
    add_common_args,
    upload_sboms,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class ProcessComponentArgs(CommonArgs):
    """
    Arguments for component SBOM processing.
    """


def parse_args() -> ProcessComponentArgs:
    """
    Parse command line arguments for component SBOM processing.

    Returns:
        ProcessComponentArgs: Parsed arguments.
    """
    parser = ap.ArgumentParser()
    add_common_args(parser)
    args = parser.parse_args()

    # the snapshot_spec is joined with the data_dir as previous tasks provide
    # the path as relative to the dataDir
    return ProcessComponentArgs(
        data_dir=args.data_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
    )


def augment_component_sboms(
    sbom_path: Path, snapshot_spec: Path, release_id: str
) -> None:
    """
    Augment component SBOMs using the mobster augment command.

    Args:
        sbom_path: Path where the SBOM will be saved.
        snapshot_spec: Path to snapshot specification file.
        release_id: Release ID to store in SBOM file.
    """
    subprocess.run(
        [
            "mobster",
            "--verbose",
            "augment",
            "--output",
            sbom_path,
            "oci-image",
            "--snapshot",
            snapshot_spec,
            "--release-id",
            release_id,
        ],
        check=True,
    )


async def process_component_sboms(args: ProcessComponentArgs) -> None:
    """
    Process component SBOMs by augmenting and uploading them.

    Args:
        args: Arguments containing data directory and configuration.
    """
    sbom_dir = args.data_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)

    augment_component_sboms(sbom_dir, args.snapshot_spec, args.release_id)
    await upload_sboms(sbom_dir, args.atlas_api_url, args.retry_s3_bucket)


def main() -> None:
    """
    Main entry point for component SBOM processing.
    """
    setup_logging(verbose=True)
    args = parse_args()
    asyncio.run(process_component_sboms(args))
