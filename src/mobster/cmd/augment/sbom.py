"""A module for augmenting SBOM documents."""

import logging
from typing import Any

from mobster.cmd.augment.bom import (
    AugmentConfig,
    BOMAugmenter,
    get_augment_config_from_cli_args,
)
from mobster.cmd.augment.handlers import SPDXVersion2
from mobster.cmd.base import Command
from mobster.error import SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci import cosign
from mobster.oci.artifact import BOM
from mobster.release import (
    ReleaseId,
    ReleaseRepository,
    make_snapshot,
)

LOGGER = logging.getLogger(__name__)


class AugmentImageCommand(Command):
    """
    Command for augmenting OCI image SBOMs.
    """

    @property
    def name(self) -> str:
        """
        Name of the augment command used for logging purposes.
        """
        return "AugmentImageCommand"

    async def execute(self) -> Any:
        """
        Update OCI image SBOMs based on the supplied args.
        """
        digest = None
        if self.cli_args.reference:
            _, digest = self.cli_args.reference.split("@", 1)

        config = get_augment_config_from_cli_args(self.cli_args)

        snapshot = await make_snapshot(self.cli_args.snapshot, digest, config.semaphore)

        augmenter = SBOMAugmenter()
        if not all(await augmenter.augment_boms(config, snapshot)):
            self.exit_code = 1

    async def save(self) -> None:
        """
        This method is now a no-op since SBOMs are written directly during the
        augmentation process to avoid accumulating SBOMs in memory.
        """


class SBOMAugmenter(BOMAugmenter):
    """
    BOM augmenter implementation for SBOMs.
    """

    async def load_bom(self, image: Image, config: AugmentConfig) -> BOM:
        """Fetch a fresh SBOM and verify its digest when verification is enabled."""
        sbom = await config.cosign.fetch_sbom(image)
        if config.verify and not sbom.signature_verified:
            # Only clients that support provenance fetch shall
            # use it for SBOM verification
            await self.verify_sbom(sbom, image, config.cosign)
        return sbom

    @staticmethod
    async def verify_sbom(
        sbom: BOM, image: Image, cosign_client: cosign.SupportsFetch
    ) -> None:
        """
        Verify that the sha256 digest of the specified SBOM matches the value of
        SBOM_BLOB_URL in the provenance for the supplied image. Cosign is used to
        fetch the provenance. If it doesn't match, an SBOMVerificationError is
        raised.

        Args:
            sbom: The sbom to verify
            image: Image to verify the sbom for
            cosign_client: Implementation of the fetch protocol

        Raises:
            SBOMVerificationError:
                upon failed verification
        """

        prov = await cosign_client.fetch_latest_provenance(image)
        prov_sbom_digest = prov.sbom_digest(image.digest)
        if prov_sbom_digest is None:
            raise SBOMVerificationError(
                f"Provenance does not contain SBOM_BLOB_URL for image {image}."
            )

        if prov_sbom_digest != sbom.digest:
            raise SBOMVerificationError(
                f"Digest {prov_sbom_digest} of SBOM for image {image} in "
                f"the provenance does not match the actual digest of "
                f"the sbom {sbom.digest}"
            )

    @staticmethod
    def update_bom_in_situ(
        repository: ReleaseRepository,
        sbom: BOM,
        cpes: list[str],
        release_id: ReleaseId | None = None,
    ) -> bool:
        """
        Determine the matching SBOM handler and update the SBOM with release-time
        information in situ.

        Args:
            repository: The repository the image is released to
            sbom: SBOM parsed as dictionary
            cpes: List of string CPEs to add to the SBOM
            release_id: Release id to be added to the SBOM's annotations, optional
        """

        if (sbom.format not in SPDXVersion2.supported_versions) and isinstance(
            sbom.image, IndexImage
        ):
            return False
        return BOMAugmenter.update_bom_in_situ(repository, sbom, cpes, release_id)
