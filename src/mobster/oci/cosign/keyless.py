"""Module for using Keyless Cosign for SBOM attestation and fetching"""

import logging
import os.path
import typing
from pathlib import Path

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.artifact import BOM, SLSAProvenance
from mobster.oci.cosign.attestation_utils import (
    get_cosign_attestation_type,
    get_latest_provenance_from_bytes,
    get_sbom_from_attestation_bytes,
)
from mobster.oci.cosign.config import (
    SignConfig,
    VerifyConfig,
)
from mobster.oci.cosign.protocol import SupportsFetch, SupportsSign
from mobster.sbom.detect import BOMFormat
from mobster.utils import run_async_subprocess

logger = logging.getLogger(__name__)

# pylint: disable=duplicate-code


def check_tuf() -> bool:
    """
    Check if Cosign has been initialized with TUF context.

    Returns:
        True if Cosign has been initialized with TUF context, False otherwise
    """
    return Path(os.path.expanduser("~/.sigstore/root/")).exists()


class KeylessSBOMFetcher(SupportsFetch):
    """
    Keyless Cosign client, uses Rekor and patterns for OIDC claims for
    verification. Requires that the host machine ran `cosign initialize`
    with correct TUF parameters previously.
    """

    # pylint: disable=too-few-public-methods

    def __init__(self, config: VerifyConfig):
        if not check_tuf():
            raise SBOMError(
                "Cannot fetch SBOM verifiably, TUF has not been initialized."
            )
        if not config.keyless_verify_config:
            raise SBOMError(
                "Cannot fetch SBOM verifiably, missing "
                "OIDC issuer or identity information."
            )
        self.config = config.keyless_verify_config

    async def _verify_attestation(
        self,
        image: Image,
        attestation_type: typing.Literal[
            "slsaprovenance02", "slsaprovenance1", "spdxjson", "cyclonedx"
        ],
    ) -> list[bytes]:
        """
        Verify and fetch attestations for a container image using cosign.

        Runs ``cosign verify-attestation`` with the configured public key to
        retrieve attestation payloads of the given type.

        Args:
            image: The container image to verify attestations for.
            attestation_type: The predicate type of the attestation to verify.

        Returns:
            A list of raw attestation payloads, one per line of cosign output.
            Returns an empty list if no attestations match the predicate type.

        Raises:
            SBOMError: If cosign verification fails for a reason other than
                a missing predicate type.
        """

        with make_oci_auth_file(image.reference) as authfile:
            # We ignore the transparency log, because as of now, Konflux releases
            # don't publish to Rekor.
            cmd = [
                "cosign",
                "verify-attestation",
                "--certificate-oidc-issuer",
                self.config.oidc_issuer,
                "--certificate-identity-regexp",
                str(self.config.identity_pattern),
                "--type",
                attestation_type,
                image.reference,
            ]
            logger.debug("Executing for %s command '%s'", image, " ".join(cmd))
            code, stdout, stderr = await run_async_subprocess(
                cmd,
                env={"DOCKER_CONFIG": str(authfile.parent)},
                retry_times=3,
            )

        if code != 0:
            stderr_str = stderr.decode()
            if "none of the attestations matched the predicate type" in stderr_str:
                return []

            raise SBOMError(
                f"Failed to fetch attestation for {image}: {stderr.decode()}."
            )

        return stdout.splitlines()

    async def fetch_sbom(self, image: Image) -> BOM:
        raw_attestation = b""
        with make_oci_auth_file(image.reference) as authfile:
            for _attempt in range(4):
                # Retry 3 times, but switch the expected attestation type
                # within each attempt
                for sbom_spec in "spdxjson", "cyclonedx":
                    command = [
                        "cosign",
                        "verify-attestation",
                        "--certificate-oidc-issuer",
                        self.config.oidc_issuer,
                        "--certificate-identity-regexp",
                        str(self.config.identity_pattern),
                        "--type",
                        sbom_spec,
                        image.reference,
                    ]
                    logger.debug(
                        "Executing for %s command '%s'", image, " ".join(command)
                    )
                    code, stdout, stderr = await run_async_subprocess(
                        command, env={"DOCKER_CONFIG": str(authfile.parent)}
                    )
                    if code == 0 and (
                        raw_lines := [line for line in stdout.splitlines() if line]
                    ):
                        raw_attestation = raw_lines[-1]
                        break
            if not raw_attestation:
                raise SBOMError(
                    f"Failed to fetch attestation for {image}: {stderr.decode()}."
                )
            return get_sbom_from_attestation_bytes(
                raw_attestation, image, signature_verified=True
            )

    async def fetch_latest_provenance(self, image: Image) -> SLSAProvenance:
        """
        Fetch the latest provenance based on the supplied image based on the
        time the image build finished.

        Args:
            image: Image to fetch the provenances of
        """

        raw_provenances = []

        for att_type in ("slsaprovenance02", "slsaprovenance1"):
            raw_provenances.extend(await self._verify_attestation(image, att_type))
        latest_provenance = await get_latest_provenance_from_bytes(raw_provenances)
        if not latest_provenance:
            raise SBOMError(f"No provenances parsed for image {image}.")
        return latest_provenance

    @staticmethod
    def is_sbom_verified() -> bool:
        """
        SBOMs are downloaded using verify-attestation,
        this method does not need Provenance verification.
        """
        return True


class KeylessSigner(SupportsSign):
    """
    Cosign signing client using Keyless signatures.
    """

    # pylint: disable=too-few-public-methods
    def __init__(self, config: SignConfig):
        if (
            not check_tuf()
            or not config.url_config.oidc_urls
            or not config.url_config.ca_urls
            or not config.url_config.rekor_tlog_urls
            or not config.keyless_token_file
        ):
            raise SBOMError(
                "Cannot attest SBOM, insufficient signing configuration was provided."
            )
        self.config = config

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: BOMFormat,
    ) -> None:
        with self.config.url_config.file() as config_file:
            cosign_command = [
                "cosign",
                "attest",
                "--signing-config",
                str(config_file.absolute()),
                "--yes",
                "--type",
                get_cosign_attestation_type(sbom_format),
                "--identity-token",
                str(self.config.keyless_token_file),
                "--predicate",
                str(sbom_path),
                image_ref,
            ]
            with make_oci_auth_file(image_ref) as authfile:
                cosign_env = {"DOCKER_CONFIG": str(authfile.parent)}
                code, _, stderr = await run_async_subprocess(
                    cosign_command,
                    env=cosign_env,
                    retry_times=3,
                )
        if code:
            raise SBOMError(
                f"Could not attest SBOM ({' '.join(cosign_command)}) "
                f"failed with code {code}, STDERR: {stderr.decode()}",
            )
