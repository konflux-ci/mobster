"""
Script used for processing component SBOMs in Tekton task.
"""

import argparse as ap
import asyncio
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from mobster.cmd.augment import AugmentConfig, SBOMRefDetail, augment_sboms
from mobster.error import SBOMError
from mobster.log import setup_logging
from mobster.oci.cosign import Cosign, CosignClient, CosignConfig, RekorConfig
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
        cosign_config: Config for cosign
    """

    augment_concurrency: int
    attestation_concurrency: int
    cosign_config: CosignConfig
    rekor_config: RekorConfig | None = None


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
    parser.add_argument("--attest-concurrency", type=int, default=4)
    parser.add_argument(
        "--rekor-key",
        type=Path,
        help="The public key file of the rekor server used for SBOM "
        "attestation within a registry",
        default=None,
    )
    parser.add_argument(
        "--rekor-url", type=str, help="The URL of the Rekor server", default=None
    )
    parser.add_argument(
        "--sign-key",
        type=str,
        help="The signing (private) key file or k8s secret to use when signing "
        "OCI attestation with SBOMs. The command just attaches "
        "an SBOM if this argument is unfilled.",
        required=True,
    )
    parser.add_argument(
        "--verify-key",
        type=str,
        help="The cosign verification key for attest downloading and verification.",
        required=True,
    )
    parser.add_argument(
        "--sign-password",
        type=str,
        default="",
        help="The password protecting the signing key.",
    )
    args = parser.parse_args()
    cosign_config = CosignConfig(
        sign_key=args.sign_key,
        verify_key=args.verify_key,
        sign_password=args.sign_password.encode("utf-8"),
    )
    rekor_config = None
    if (rekor_key := args.rekor_key) and (rekor_url := args.rekor_url):
        rekor_config = RekorConfig(rekor_key=rekor_key, rekor_url=rekor_url)

    # the snapshot_spec is joined with the data_dir as previous tasks provide
    # the path as relative to the dataDir
    return ProcessComponentArgs(
        data_dir=args.data_dir,
        result_dir=args.data_dir / args.result_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
        augment_concurrency=args.augment_concurrency,
        upload_concurrency=args.upload_concurrency,
        attestation_concurrency=args.attest_concurrency,
        labels=args.labels,
        atlas_retries=args.atlas_retries,
        cosign_config=cosign_config,
        rekor_config=rekor_config,
        skip_upload=args.skip_upload,
    )


async def augment_component_sboms(
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    sbom_path: Path,
    snapshot_spec: Path,
    release_id: ReleaseId,
    cosign_client: Cosign,
    augment_concurrency: int,
    attest_concurrency: int,
) -> None:
    """
    Augment component SBOMs using the mobster augment command.

    Args:
        sbom_path: Path where the SBOM will be saved.
        snapshot_spec: Path to snapshot specification file.
        release_id: Release ID to store in SBOM file.
        cosign_client: Cosign client
        augment_concurrency: Maximum number of concurrent augmentation operations.
        attest_concurrency: Maximum number of concurrent OCI attestation operations.
    """
    semaphore = asyncio.Semaphore(augment_concurrency)
    snapshot = await make_snapshot(snapshot_spec, None, semaphore)
    config = AugmentConfig(
        cosign=cosign_client,
        verify=True,
        semaphore=semaphore,
        output_dir=sbom_path,
        release_id=release_id,
    )
    result_details = await augment_sboms(config, snapshot)
    if not all(result_details):
        raise SBOMError("Could not enrich all SBOMs!")
    LOGGER.debug("Successfully augmented SBoms for ReleaseId: %s", str(release_id))

    if not cosign_client.can_sign():
        return

    semaphore = asyncio.Semaphore(attest_concurrency)
    push_tasks = [
        attest_sbom_to_registry(
            result_detail,
            cosign_client,
            semaphore,
        )
        for result_detail in result_details
        if result_detail and result_detail.attestation_valid
    ]
    push_results = await asyncio.gather(*push_tasks)
    if not all(push_results):
        raise SBOMError("Could not attest all SBOMs!")


async def process_component_sboms(args: ProcessComponentArgs) -> None:
    """
    Process component SBOMs by augmenting and uploading them.

    Args:
        args: Arguments containing data directory and configuration.
    """
    s3 = connect_with_s3(args.retry_s3_bucket)

    if not args.skip_upload and s3:
        LOGGER.info("Uploading snapshot to S3 with release_id=%s", args.release_id)
        await upload_snapshot(s3, args.snapshot_spec, args.release_id)
    else:
        LOGGER.debug(
            "skip_upload=%s, so no snapshot / "
            "release data upload to S3, for release_id=%s",
            args.skip_upload,
            args.release_id,
        )

    cosign_client = CosignClient(
        cosign_config=args.cosign_config,
        rekor_config=args.rekor_config,
    )
    LOGGER.info("Starting SBOM augmentation")

    with tempfile.TemporaryDirectory() as sbom_dir:
        await augment_component_sboms(
            Path(sbom_dir),
            args.snapshot_spec,
            args.release_id,
            cosign_client,
            args.augment_concurrency,
            args.attestation_concurrency,
        )

        if args.skip_upload:
            LOGGER.debug(
                "skip_upload=%s, so no upload to TPA, for release_id=%s",
                args.skip_upload,
                args.release_id,
            )
        else:
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


async def attest_sbom_to_registry(
    sbom_ref_detail: SBOMRefDetail,
    cosign_client: Cosign,
    semaphore: asyncio.Semaphore,
) -> bool:
    """
    Use cosign client to push the augmented component SBOM to the registry
    as an attestation of the image.
    Args:
        sbom_ref_detail: Info about SBOM file, its release destination and its type
        cosign_client: The cosign client used for the communication with the registry
        semaphore: Semaphore for throttling concurrency
    Returns:
        True if the push was successful, False otherwise
    """
    if not cosign_client.can_sign():
        raise ValueError(
            f"Could not attest image {sbom_ref_detail.reference} "
            f"because no signing key was provided!"
        )
    async with semaphore:
        try:
            await cosign_client.attest_sbom(
                sbom_path=sbom_ref_detail.path,
                image_ref=sbom_ref_detail.reference,
                sbom_format=sbom_ref_detail.sbom_format,
            )
            LOGGER.debug("Successfully attested image %s.", sbom_ref_detail.reference)
        except SBOMError:
            LOGGER.exception("Could not attest SBOM because of a cosign error.")
            return False
        except Exception:  # pylint: disable=broad-exception-caught
            LOGGER.exception("Could not attest SBOM because of an unknown error.")
            return False
    return True


def main() -> None:
    """
    Main entry point for component SBOM processing.
    """
    setup_logging(verbose=True)
    args = parse_args()
    asyncio.run(process_component_sboms(args))
