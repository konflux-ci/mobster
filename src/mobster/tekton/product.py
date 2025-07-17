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
class ProcessProductArgs(CommonArgs):
    release_data: Path


def parse_args() -> ProcessProductArgs:
    parser = ap.ArgumentParser()
    add_common_args(parser)
    parser.add_argument("--release-data", type=Path, required=True)
    args = parser.parse_args()

    return ProcessProductArgs(
        data_dir=args.data_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        release_data=args.data_dir / args.release_data,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
    )


def create_product_sbom(
    sbom_path: Path, snapshot_spec: Path, release_data: Path
) -> None:
    res = subprocess.run(
        [
            "mobster",
            "--verbose",
            "generate",
            "--output",
            sbom_path,
            "product",
            "--snapshot",
            snapshot_spec,
            "--release-data",
            release_data,
        ]
    )
    res.check_returncode()  # TODO:


async def process_product_sboms(args: ProcessProductArgs) -> None:
    sbom_dir = args.data_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)
    sbom_path = sbom_dir / "sbom.json"

    create_product_sbom(sbom_path, args.snapshot_spec, args.release_data)
    await upload_sboms(sbom_dir, args.atlas_api_url, args.retry_s3_bucket)


def main():
    setup_logging(verbose=True)
    args = parse_args()
    asyncio.run(process_product_sboms(args))
