"""
Module for CBOM augmenting.
"""

import asyncio
import logging
from typing import Any

from mobster.cmd.augment.bom import (
    AugmentConfig,
    BOMAugmenter,
    BOMRefDetail,
    get_augment_config_from_cli_args,
)
from mobster.cmd.base import Command
from mobster.image import Image
from mobster.oci.artifact import BOM
from mobster.oci.oras import CBOMFetchError, OrasClient
from mobster.release import Component, make_snapshot

LOGGER = logging.getLogger(__name__)


class AugmentCBOMCommand(Command):
    """
    The CBOM Augment command.
    """

    async def execute(self) -> Any:
        digest = None
        if self.cli_args.reference:
            _, digest = self.cli_args.reference.split("@", 1)

        config = get_augment_config_from_cli_args(self.cli_args)

        snapshot = await make_snapshot(self.cli_args.snapshot, digest, config.semaphore)

        augmenter = CBOMAugmenter()
        if not all(await augmenter.augment_boms(config, snapshot)):
            self.exit_code = 1

    async def save(self) -> None:
        """no-op"""


class CBOMAugmenter(BOMAugmenter):
    """
    The implementation of BOM augmenter for CBOMs.
    """

    async def load_bom(self, image: Image, config: AugmentConfig) -> BOM | None:
        """
        Load the build-time CBOM for the given image.
        Args:
            image: The image the CBOM is attached to.
            config: The augmentation config.

        Returns:
            The CBOM if found, None otherwise.
        """
        provenance = await config.cosign.fetch_latest_provenance(image)
        cbom_url = provenance.cbom_blob_url()
        if not cbom_url:
            LOGGER.info("No CBOM_BLOB_URL found for the image %s", image.reference)
            return None
        try:
            return await OrasClient.fetch_cbom(cbom_url, image)
        except CBOMFetchError:
            LOGGER.warning(
                "Could not fetch CBOM from CBOM_BLOB_URL. Nothing to augment.",
                exc_info=True,
            )
            return None

    async def update_component_boms(
        self, config: AugmentConfig, component: Component
    ) -> list[BOMRefDetail | None]:
        """
        Update all component BOMs. CBOM is only one per component.
        Args:
            config: The Augmentation Configuration.
            component: The Component being augmented.

        Returns:
            Augmentation result reference details.
        """
        return await asyncio.gather(
            *[
                self.update_bom(config, repo, component.image)
                for repo in component.release_repositories
            ]
        )
