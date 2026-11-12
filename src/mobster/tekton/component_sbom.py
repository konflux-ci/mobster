"""
Script used for processing component SBOMs in Tekton task.
"""

import argparse as ap
import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from mobster.cmd.augment.bom import BOMRefDetail
from mobster.cmd.augment.sbom import SBOMAugmenter
from mobster.error import SBOMError
from mobster.log import setup_logging
from mobster.oci import cosign
from mobster.tekton.common import (
    add_common_args,
)
from mobster.tekton.component import (
    ComponentBOMHandler,
    ProcessComponentArgs,
    add_component_args,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class ProcessComponentSBOMArgs(ProcessComponentArgs):
    """
    Arguments for component SBOM processing.

    Attributes:
        attestation_concurrency: maximum number of concurrent cosign attest operations
        cosign_sign_config: Config for cosign signing
    """

    attestation_concurrency: int
    cosign_sign_config: cosign.SignConfig


def _add_component_sbom_args(parser: ap.ArgumentParser) -> None:
    parser.add_argument("--attest-concurrency", type=int, default=4)
    parser.add_argument(
        "--sign-key",
        type=str,
        help="The signing (private) key file or k8s secret to use when signing "
        "OCI attestation with SBOMs. The command just attaches "
        "an SBOM if this argument is unfilled.",
        default=None,
    )
    parser.add_argument(
        "--sign-password",
        type=str,
        default="",
        help="The password protecting the signing key.",
    )
    parser.add_argument(
        "--oidc-token",
        type=Path,
        help="OIDC token for signing written in a file",
        default=None,
    )


def parse_args(cli_args: Sequence[str] | None = None) -> ProcessComponentSBOMArgs:
    """
    Parse command line arguments for component SBOM processing.

    Returns:
        ProcessComponentArgs: Parsed arguments.
    """
    parser = ap.ArgumentParser()
    add_common_args(parser)
    add_component_args(parser)
    _add_component_sbom_args(parser)

    args = parser.parse_args(args=cli_args)

    static_sign_config = None
    if args.sign_key:
        static_sign_config = cosign.StaticSignConfig(
            sign_key=args.sign_key, sign_password=args.sign_password.encode("utf-8")
        )
    sign_config = cosign.SignConfig(
        static_sign_config=static_sign_config,
        url_config=(
            cosign.URLSigningConfig()
            .set_tlog_url(args.rekor_url)
            .set_fulcio_url(args.fulcio_url)
            .set_issuer_url(args.oidc_issuer)
        ),
        keyless_token_file=args.oidc_token,
    )
    keyless_verify_config = None
    if args.oidc_identity_pattern and args.oidc_issuer:
        keyless_verify_config = cosign.KeylessVerifyConfig(
            identity_pattern=args.oidc_identity_pattern, oidc_issuer=args.oidc_issuer
        )
    verify_config = cosign.VerifyConfig(
        static_verify_key=args.verify_key,
        keyless_verify_config=keyless_verify_config,
    )

    # the snapshot_spec is joined with the data_dir as previous tasks provide
    # the path as relative to the dataDir
    return ProcessComponentSBOMArgs(
        data_dir=args.data_dir,
        result_dir=args.data_dir / args.result_dir,
        snapshot_spec=args.data_dir / args.snapshot_spec,
        release_data=args.data_dir / args.release_data,
        atlas_api_url=args.atlas_api_url,
        retry_s3_bucket=args.retry_s3_bucket,
        release_id=args.release_id,
        augment_concurrency=args.augment_concurrency,
        upload_concurrency=args.upload_concurrency,
        attestation_concurrency=args.attest_concurrency,
        labels=args.labels,
        atlas_retries=args.atlas_retries,
        skip_upload=args.skip_upload,
        skip_s3_upload=False,
        cosign_sign_config=sign_config,
        cosign_verify_config=verify_config,
    )


class ComponentSBOMHandler(ComponentBOMHandler[ProcessComponentSBOMArgs]):
    """
    Class for e2e handling of release-time SBOMs.
    """

    augmenter_class = SBOMAugmenter

    @staticmethod
    async def attest_boms(
        args: ProcessComponentSBOMArgs, results: list[BOMRefDetail]
    ) -> None:
        cosign_signer = cosign.get_cosign_signer(args.cosign_sign_config)
        semaphore = asyncio.Semaphore(args.augment_concurrency)
        attest_tasks = [
            attest_sbom_to_registry(result, cosign_signer, semaphore)
            for result in results
        ]
        if not all(await asyncio.gather(*attest_tasks)):
            raise SBOMError("Could not push attested SBOMs to registry!")

    def assess_results(self, results: list[BOMRefDetail | None]) -> list[BOMRefDetail]:
        if not all(results):
            raise SBOMError("Could not augment all SBOMs!")
        return super().assess_results(results)


async def attest_sbom_to_registry(
    sbom_ref_detail: BOMRefDetail,
    cosign_signer: cosign.SupportsSign,
    semaphore: asyncio.Semaphore,
) -> bool:
    """
    Use cosign client to push the augmented component SBOM to the registry
    as an attestation of the image.
    Args:
        sbom_ref_detail: Info about SBOM file, its release destination and its type
        cosign_signer: The cosign client used for the communication with the registry
        semaphore: Semaphore for throttling concurrency
    Returns:
        True if the push was successful, False otherwise
    """
    async with semaphore:
        try:
            await cosign_signer.attest_sbom(
                sbom_path=sbom_ref_detail.path,
                image_ref=sbom_ref_detail.reference,
                sbom_format=sbom_ref_detail.sbom_format,
            )
            method = (
                "static"
                if isinstance(cosign_signer, cosign.StaticKeySigner)
                else "keyless"
            )
            LOGGER.debug(
                "Successfully attested image %s using %s signing method.",
                sbom_ref_detail.reference,
                method,
            )
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
    handler = ComponentSBOMHandler()
    asyncio.run(handler.process_component_boms(args))
