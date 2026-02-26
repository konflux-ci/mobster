"""Module for using Keyless Cosign for SBOM attestation and fetching"""

import os.path
from pathlib import Path

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.artifact import SBOM, Provenance02, SBOMFormat
from mobster.oci.cosign.attestation_utils import get_cosign_attestation_type
from mobster.oci.cosign.config import (
    KeylessSignConfig,
    RekorConfig,
    SignConfig,
    VerifyConfig,
)
from mobster.oci.cosign.protocol import SupportsFetch, SupportsSign
from mobster.utils import run_async_subprocess


def check_tuf() -> bool:
    """
    Check if Cosign has been initialized with TUF context.
    Returns:
        True if Cosign has been initialized with TUF context, False otherwise.
    """
    return Path(os.path.expanduser("~/.sigstore/root/")).exists()


class KeylessSBOMFetcher(SupportsFetch):
    """
    Keyless Cosign client, uses Rekor and patterns for OIDC claims for
    verification. Requires that the host machine ran `cosign initialize`
    with correct TUF parameters previously.
    """

    def __init__(self, config: VerifyConfig):
        if not check_tuf():
            raise SBOMError(
                "Cannot fetch SBOM verifiably, TUF has not been initialized."
            )
        self.keyless_config = config.keyless_verify_config
        self.rekor_config = config.rekor_config

    async def fetch_latest_provenance(
        self, image: Image
    ) -> Provenance02:  # pragma: no cover
        # This does not have to be present in the final implementation,
        # we may want to consolidate it into SBOM fetching + verification
        raise NotImplementedError("To be implemented or deleted in ISV-6681")

    async def fetch_sbom(self, image: Image) -> SBOM:  # pragma: no cover
        # This should work even with unauthenticated cosign (no Rekor and no TUF)
        # while also being able to fall back to fetching attached SBOMs instead
        # of attested ones.
        raise NotImplementedError("To be implemented in ISV-6681")


class KeylessSigner(SupportsSign):
    """
    Cosign signing client using Keyless signatures
    """

    # pylint: disable=too-few-public-methods
    def __init__(self, config: SignConfig):
        if (
            not check_tuf()
            or config.keyless_config is None
            or config.rekor_config is None
        ):
            raise SBOMError(
                "Cannot attest SBOM, no signing configuration was provided."
            )
        self.keyless_config: KeylessSignConfig = config.keyless_config
        self.rekor_config: RekorConfig = config.rekor_config

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: SBOMFormat,
    ) -> None:
        cosign_command = [
            "cosign",
            "attest",
            "--yes",
            "--type",
            get_cosign_attestation_type(sbom_format),
            "--rekor-url",
            str(self.rekor_config.rekor_url),
            "--fulcio-url",
            str(self.keyless_config.fulcio_url),
            "--identity-token",
            str(self.keyless_config.token_file),
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
