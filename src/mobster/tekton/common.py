"""
Common utilities for Tekton tasks.
"""

import asyncio
import logging
import os
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mobster.cli import parse_tpa_labels
from mobster.cmd.generate.product import ReleaseData
from mobster.cmd.upload.upload import TPAUploadCommand, TPAUploadReport, UploadConfig
from mobster.release import ReleaseId, SnapshotModel
from mobster.tekton.s3 import S3Client

LOGGER = logging.getLogger(__name__)


class AtlasUploadError(Exception):
    """
    Raised when a non-transient Atlas error occurs.
    """


@dataclass
class CommonArgs:
    """
    Arguments common for both product and component SBOM processing.

    Attributes:
        data_dir: main data directory defined in Tekton task
        result_dir: path to directory to store results to
        snapshot_spec: path to snapshot spec file
        atlas_api_url: url of the TPA instance to use
        retry_s3_bucket: name of the S3 bucket to use for retries
        labels: labels to attach to uploaded SBOMs
        tpa_retries: how many retries for SBOM upload will be
            performed before failing
    """

    # pylint: disable=too-many-instance-attributes
    data_dir: Path
    snapshot_spec: Path
    atlas_api_url: str
    retry_s3_bucket: str
    release_id: ReleaseId
    labels: dict[str, str]
    result_dir: Path
    tpa_retries: int
    upload_concurrency: int

    def ensured_sbom_dir(self) -> Path:
        """
        Get the 'sbom' subdir, create it if not present.
        Returns:
            The Path object reference to the sbom subdir.
        """
        sbom_dir = self.data_dir / "sbom"
        sbom_dir.mkdir(exist_ok=True)
        return sbom_dir

    def to_upload_config(self) -> UploadConfig:
        """
        Creates UploadConfig from the common args.
        Returns:
            The populated UploadConfig object.
        """
        auth = TPAUploadCommand.get_oidc_auth()
        return UploadConfig(
            auth=auth,
            base_url=self.atlas_api_url,
            retries=self.tpa_retries,
            workers=self.upload_concurrency,
            paths=list(self.ensured_sbom_dir().iterdir()),
            labels=self.labels,
        )


def add_common_args(parser: ArgumentParser) -> None:
    """
    Add common command line arguments to the parser.

    Args:
        parser: The argument parser to add arguments to.
    """
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--snapshot-spec", type=Path, required=True)
    parser.add_argument("--release-id", type=ReleaseId, required=True)
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--atlas-api-url", type=str)
    parser.add_argument("--retry-s3-bucket", type=str)
    parser.add_argument(
        "--labels",
        type=parse_tpa_labels,
        help='Comma-separated "key=value" pairs denoting '
        "labels to attach to the uploaded SBOMs",
        default={},
    )
    parser.add_argument(
        "--tpa-retries",
        type=int,
        default=1,
        help="How many retries for SBOM upload will be performed "
        "before falling back to S3.",
    )


async def upload_sboms(
    config: UploadConfig,
    s3_client: S3Client | None,
) -> TPAUploadReport:
    """
    Upload SBOMs to Atlas with S3 fallback on transient errors.

    Args:
        config: TPA upload configuration object.
        s3_client: S3Client object for retry uploads, or None if no retries.

    Raises:
        ValueError: If Atlas authentication credentials are missing or if S3
            client is provided but AWS authentication credentials are missing.
        RuntimeError: If any SBOM failed to be pushed to Atlas with a
            non-transient error
    """
    if not atlas_credentials_exist():
        raise ValueError("Missing Atlas authentication.")

    LOGGER.info("Starting SBOM upload to Atlas")
    report = await upload_to_atlas(config)
    if report.has_non_transient_failures():
        raise RuntimeError(
            "SBOMs failed to be uploaded to Atlas: \n"
            + "\n".join(
                [
                    f"{path}: {message}"
                    for path, message in report.get_non_transient_errors()
                ]
            )
        )

    if report.has_transient_failures() and s3_client is not None:
        LOGGER.warning("Encountered transient Atlas error, falling back to S3.")
        await handle_atlas_transient_errors(report.transient_error_paths, s3_client)

    return report


async def handle_atlas_transient_errors(paths: list[Path], s3_client: S3Client) -> None:
    """
    Handle Atlas transient errors via the S3 retry mechanism.

    Args:
        paths: List of file paths that failed with transient errors.
        s3_client: S3 client to use for uploading failed files.

    Raises:
        ValueError: If S3 credentials aren't specified in env.
    """
    if not s3_credentials_exist():
        raise ValueError("Missing AWS authentication while attempting S3 retry.")

    await asyncio.gather(*[s3_client.upload_file(failed_sbom) for failed_sbom in paths])


async def upload_to_atlas(
    config: UploadConfig,
) -> TPAUploadReport:
    """
    Upload SBOMs to Atlas TPA instance.

    Args:
        config: Atlas SBOM upload configuration.

    Raises:
        AtlasUploadError: If a non-transient error occurs.

    Returns:
        TPAUploadReport: Parsed upload report from the upload command.
    """
    return await TPAUploadCommand.upload(config)


async def upload_to_s3(report: TPAUploadReport, client: S3Client) -> None:
    """
    Upload failed SBOMs from the report to S3.

    Args:
        report: upload report containing the failed SBOMs
        client: S3 client to use
    """
    await asyncio.gather(
        *[client.upload_file(failure.path) for failure in report.failure]
    )


def connect_with_s3(retry_s3_bucket: str | None) -> S3Client | None:
    """
    Connect with AWS S3 using S3Client.

    Args:
        retry_s3_bucket: S3 bucket name, or None to skip S3 connection.

    Returns:
        S3Client object if bucket name provided and credentials exist, None otherwise.

    Raises:
        ValueError: If bucket name is provided but AWS credentials are missing.
    """
    if not retry_s3_bucket:
        return None

    if not s3_credentials_exist():
        raise ValueError("Missing AWS authentication.")
    client = S3Client(
        bucket=retry_s3_bucket,
        access_key=os.environ["AWS_ACCESS_KEY_ID"],
        secret_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        endpoint_url=os.environ.get(
            "AWS_ENDPOINT_URL"
        ),  # configurable for testing purposes
    )

    return client


def validate_sbom_input_data(
    sbom_input_file: Path,
    obj: type[SnapshotModel] | type[ReleaseData],
) -> Any:
    """
    Validate SBOM Input data.

    Args:
        sbom_input_file: File path of SBOM input data
        obj: The data model to validate the input data file.

    Returns:
        validated_data: The input data validated by Data Model
    """
    with open(sbom_input_file, encoding="utf-8") as fp:
        validated_data = obj.model_validate_json(fp.read())
    return validated_data


async def upload_snapshot(
    s3_client: S3Client, sbom_input_file: Path, release_id: ReleaseId
) -> None:
    """
    Upload a snapshot to S3 bucket with prefix.

    Args:
        s3_client: S3Client object
        sbom_input_file: File path of SBOM input data
        release_id: The release ID to use as the object key.
    """
    snapshot = validate_sbom_input_data(sbom_input_file, SnapshotModel)
    await s3_client.upload_input_data(snapshot, release_id)


async def upload_release_data(
    s3_client: S3Client, sbom_input_file: Path, release_id: ReleaseId
) -> None:
    """
    Upload release data to S3 bucket with prefix.

    Args:
        s3_client: S3Client object
        sbom_input_file: File path of SBOM input data
        release_id: The release ID to use as the object key.
    """
    release_data = validate_sbom_input_data(sbom_input_file, ReleaseData)
    await s3_client.upload_input_data(release_data, release_id)


def atlas_credentials_exist() -> bool:
    """
    Check if Atlas TPA SSO credentials are present in environment.

    Returns:
        bool: True if all required Atlas credentials are present.
    """
    return (
        "MOBSTER_TPA_SSO_ACCOUNT" in os.environ
        and "MOBSTER_TPA_SSO_TOKEN" in os.environ
        and "MOBSTER_TPA_SSO_TOKEN_URL" in os.environ
    )


def s3_credentials_exist() -> bool:
    """
    Check if AWS S3 credentials are present in environment.

    Returns:
        bool: True if all required S3 credentials are present.
    """
    return "AWS_ACCESS_KEY_ID" in os.environ and "AWS_SECRET_ACCESS_KEY" in os.environ
