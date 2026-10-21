"""A module for attaching signed SBOM attestations to images."""

__all__ = ["AttestCommand"]

import json
import logging
from typing import Any

from mobster.cmd.base import Command
from mobster.error import SBOMError
from mobster.oci.cosign import SignConfig, URLSigningConfig, get_cosign_signer
from mobster.sbom.detect import detect_sbom_format

LOGGER = logging.getLogger(__name__)


class AttestCommand(Command):
    """
    Command for attaching a signed SBOM attestation to an image.

    This is a thin wrapper around ``cosign attest`` for uploading an SBOM as a
    signed, keyless attestation. It replaces a direct ``cosign attest``
    invocation and:

    - detects the attestation type (cyclonedx or spdxjson) from the input file,
    - retries the upload on failure,
    - passes pre-selected registry auth credentials to cosign.

    The underlying signing is performed by the keyless cosign client, which
    retries the upload and scopes the registry credentials handed to cosign.
    """

    @property
    def name(self) -> str:
        """
        Name of the attest command used for logging purposes.
        """
        return "AttestCommand"

    async def execute(self) -> Any:
        """
        Attach the SBOM to the image as a signed, keyless attestation.
        """
        sbom_path = self.cli_args.sbom_path
        image_ref = self.cli_args.image_ref

        LOGGER.info("Attesting SBOM %s to %s.", sbom_path, image_ref)

        with open(sbom_path, encoding="utf-8") as sbom_file:
            sbom_format = detect_sbom_format(json.load(sbom_file))

        url_config = (
            URLSigningConfig()
            .set_tlog_url(self.cli_args.rekor_url)
            .set_fulcio_url(self.cli_args.fulcio_url)
            .set_issuer_url(self.cli_args.oidc_issuer_url)
        )
        config = SignConfig(
            url_config=url_config,
            keyless_token_file=self.cli_args.oidc_token_path,
        )

        signer = get_cosign_signer(config)
        try:
            await signer.attest_sbom(sbom_path, image_ref, sbom_format)
            LOGGER.info("Attested SBOM %s to %s.", sbom_path, image_ref)
        except SBOMError:
            LOGGER.exception("Failed to attest SBOM to %s.", image_ref)
            self.exit_code = 1

    async def save(self) -> None:
        """
        No-op. The attestation is uploaded to the registry during execute().
        """
