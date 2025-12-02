"""Package for CLI parsing for the regeneration script"""

import argparse
import atexit
import datetime
import logging
import shutil
import tempfile
from pathlib import Path

from mobster.cli import parse_concurrency
from mobster.regenerate.base import GENERATED_SBOMS_PREFIX
from mobster.regenerate.by_release_id import (
    RegenerateReleaseArgs,
    ReleaseSBOMRegenerator,
)
from mobster.regenerate.invalid import RegenerateArgs
from mobster.regenerate.outage import RegenerateOutageArgs
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


def prepare_output_paths(output_dir: str) -> Path:
    """ensure cli-specified output paths exist for use by the regenerator"""
    if not output_dir:
        # create it as a temporary directory
        output_dir = tempfile.mkdtemp()
        # remove it on exit
        atexit.register(lambda: shutil.rmtree(output_dir))
    output_path = Path(output_dir)
    LOGGER.debug("output path: %s", output_path)
    # prepare output_path subdirs
    (output_path / S3Client.release_data_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / S3Client.snapshot_prefix).mkdir(parents=True, exist_ok=True)
    (output_path / GENERATED_SBOMS_PREFIX).mkdir(parents=True, exist_ok=True)
    return output_path


def parse_args() -> RegenerateArgs | RegenerateOutageArgs | RegenerateReleaseArgs:
    """
    Parse command line arguments for product SBOM processing.

    Returns: Parsed arguments.
    """
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()
    common_args = {
        "output_path": prepare_output_paths(args.output_dir),
        "s3_bucket_url": args.s3_bucket_url,
        "concurrency": args.concurrency,
        "dry_run": args.dry_run,
        "verbose": args.verbose,
        "fail_fast": not args.non_fail_fast,
        "tpa_base_url": args.tpa_base_url,
        "tpa_retries": args.tpa_retries,
    }
    result_args: RegenerateOutageArgs | RegenerateArgs | RegenerateReleaseArgs
    if args.command == "outage":
        result_args = RegenerateOutageArgs(
            since=args.since, until=args.until, **common_args
        )
    elif args.command == "invalid":
        result_args = RegenerateArgs(
            mobster_versions=args.mobster_versions,
            tpa_page_size=args.tpa_page_size,
            ignore_missing_releaseid=args.ignore_missing_releaseid,
            **common_args,
        )
    else:
        result_args = RegenerateReleaseArgs(
            release_ids=ReleaseSBOMRegenerator.get_releases_from_file(
                args.release_id_file
            ),
            **common_args,
        )

    LOGGER.debug(result_args)
    return result_args


def _add_outage_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--since",
        type=datetime.datetime.fromisoformat,
        required=True,
        help="When did the outage start",
    )
    parser.add_argument(
        "--until",
        type=datetime.datetime.fromisoformat,
        required=True,
        help="When did the outage end",
    )


def _add_invalid_regeneration_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mobster-versions",
        type=str,
        required=True,
        help="Comma separated list of mobster versions to query for, "
        "e.g.:  0.2.1,0.5.0",
    )
    parser.add_argument(
        "--ignore-missing-releaseid",
        action="store_true",
        help="Ignore (and don't fail on) any SBOM which is missing ReleaseId",
    )


def _add_release_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--release-id-file",
        type=Path,
        required=True,
        help="Path to a file with SBOM IDs to use for regeneration, one per line",
    )


def add_args(parser: argparse.ArgumentParser) -> None:
    """
    Add command line arguments to the parser.

    Args:
        parser: argument parser to add commands to
    """
    parser.add_argument(
        "--output-dir",
        type=str,
        required=False,
        help="Path to the output directory. "
        "If it doesn't exist, it will be automatically created. "
        "If not specified, a TemporaryDirectory will be created.",
    )

    parser.add_argument(
        "--tpa-base-url",
        type=str,
        required=True,
        help="URL of the TPA server",
    )

    parser.add_argument(
        "--s3-bucket-url",
        type=str,
        required=True,
        help="AWS S3 bucket URL with release data and snapshots",
    )

    parser.add_argument(
        "--concurrency",
        type=parse_concurrency,
        default=8,
        help="concurrency limit for S3 client (non-zero integer)",
    )

    parser.add_argument(
        "--tpa-retries",
        type=int,
        default=1,
        help="total number of attempts for TPA requests",
    )

    # int
    parser.add_argument(
        "--tpa-page-size",
        type=int,
        default=50,
        help="paging size (how many SBOMs) for query response sets",
    )

    # bool
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in 'dry run' only mode (skips destructive TPA IO)",
    )

    # bool
    parser.add_argument(
        "--non-fail-fast",
        action="store_true",
        help="Don't fail and exit on first regen error",
    )

    # bool
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Run in verbose mode (additional logs/trace)",
    )

    subparser = parser.add_subparsers(dest="command", required=True)
    regenerate_invalid_parser = subparser.add_parser("invalid")
    regenerate_outage_parser = subparser.add_parser("outage")
    regenerate_release_parser = subparser.add_parser("release")
    _add_outage_args(regenerate_outage_parser)
    _add_invalid_regeneration_args(regenerate_invalid_parser)
    _add_release_args(regenerate_release_parser)
