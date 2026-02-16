"""Module for using Keyless Cosign for SBOM attestation and fetching"""

import os.path
from dataclasses import dataclass
from pathlib import Path

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.artifact import SBOM, Provenance02, SBOMFormat
from mobster.oci.cosign import Cosign, get_cosign_attestation_type
from mobster.utils import run_async_subprocess


@dataclass
class KeylessConfig:
    """
    Configuration for Keyless Cosign
    """

    fulcio_url: str | None = None
    rekor_url: str | None = None
    token_file: Path | None = None
    issuer_pattern: str = ".*"
    identity_pattern: str = ".*"


class KeylessCosign(Cosign):
    """
    Keyless Cosign client, used OIDC tokens for signing
    and Rekor for verification. Requires that the host
    machine ran `cosign initialize` with correct TUF
    parameters previously.
    """

    def __init__(self, config: KeylessConfig):
        self.config = config

    @staticmethod
    def _check_tuf() -> bool:
        """
        Check if Cosign has been initialized with TUF context.
        Returns:
            True if Cosign has been initialized with TUF context, False otherwise.
        """
        return Path(os.path.expanduser("~/.sigstore/root/")).exists()

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: SBOMFormat,
    ) -> None:
        # Translate SPDX format to a cosign-supported version. See
        # https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md#options
        cosign_command = [
            "cosign",
            "attest",
            "--yes",
            "--type",
            get_cosign_attestation_type(sbom_format),
            "--rekor-url",
            str(self.config.rekor_url),
            "--fulcio-url",
            str(self.config.fulcio_url),
            "--identity-token",
            str(self.config.token_file),
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

    def can_sign(self) -> bool:
        return (
            self._check_tuf()
            and self.config.fulcio_url is not None
            and self.config.rekor_url is not None
            and self.config.token_file is not None
            and self.config.token_file.exists()
        )

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
