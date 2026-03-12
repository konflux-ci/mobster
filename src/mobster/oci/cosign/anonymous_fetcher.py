"""Cosign fetch client without any secrets for verification"""

import logging

from mobster.error import SBOMError
from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.artifact import SBOM
from mobster.oci.cosign.attestation_utils import get_sbom_from_attestation_bytes
from mobster.oci.cosign.protocol import SupportsFetch
from mobster.utils import run_async_subprocess

logger = logging.getLogger(__name__)


class AnonymousFetcher(SupportsFetch):
    """
    Cosign fetch client with no secrets for verification
    """

    # pylint: disable=too-few-public-methods

    @staticmethod
    async def _download_attestation(
        image_ref: str, env: dict[str, str]
    ) -> bytes | None:
        """
        Download SBOM attestation bytes. Make sure to run this function
        from within the context of make_oci_auth_file. Tries both SPDX
        and CycloneDX formats (in this order).
        Args:
            image_ref: Image reference
        Returns: byte representation of the latest attestation
        """
        for sbom_type in "spdxjson", "cyclonedx":
            cmd = [
                "cosign",
                "download",
                "attestation",
                "--predicate-type",
                sbom_type,
                image_ref,
            ]
            logger.debug("Executing for %s command '%s'", image_ref, " ".join(cmd))
            code, stdout, stderr = await run_async_subprocess(cmd, env=env)
            if code == 0 and (
                raw_lines := [line for line in stdout.splitlines() if line]
            ):
                return raw_lines[-1]
            logger.warning(
                "Cosign fetching attestation of type %s failed for %s with output %s",
                sbom_type,
                image_ref,
                stderr,
            )
        return None

    async def fetch_sbom(self, image: Image) -> SBOM:
        """
        Fetch and parse the SBOM for the supplied image.

        Args:
            image (Image): Image to fetch the SBOM of.
        """
        image_ref = image.reference
        with make_oci_auth_file(image_ref) as authfile:
            env = {"DOCKER_CONFIG": str(authfile.parent)}
            for _attempt in range(4):
                # Retry 3 times, but switch between attached
                # and the 2 supported attested methods
                code, stdout, stderr = await run_async_subprocess(
                    ["cosign", "download", "sbom", image_ref],
                    env=env,
                )
                if code == 0:
                    return SBOM.from_cosign_output(stdout, image_ref)
                logger.debug(
                    "Cosign SBOM fetching failed for %s with output %s",
                    image_ref,
                    stderr,
                )
                att_bytes = await self._download_attestation(image_ref, env)
                if att_bytes:
                    return get_sbom_from_attestation_bytes(att_bytes, image_ref)
        raise SBOMError(
            f"Failed to fetch SBOM {image_ref}, it is not attached, nor attested."
        )
