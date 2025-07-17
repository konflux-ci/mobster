import argparse as ap
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
    pass


def parse_args() -> ProcessComponentArgs:
    parser = ap.ArgumentParser()
    add_common_args(parser)
    args = parser.parse_args()

    return ProcessComponentArgs(
        data_dir=args.data_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
    )


def augment_component_sboms(sbom_path: Path, snapshot_spec: Path) -> None:
    res = subprocess.run(
        [
            "mobster",
            "--verbose",
            "augment",
            "--output",
            sbom_path,
            "oci-image",
            "--snapshot",
            snapshot_spec,
        ]
    )
    res.check_returncode()  # TODO:


def process_component_sboms(args: ProcessComponentArgs) -> None:
    sbom_dir = args.data_dir / "sbom"
    sbom_dir.mkdir(exist_ok=True)

    augment_component_sboms(sbom_dir, args.snapshot_spec)
    upload_sboms(sbom_dir, args.atlas_api_url, args.retry_s3_bucket)


def main():
    setup_logging(verbose=True)
    args = parse_args()
    process_component_sboms(args)
