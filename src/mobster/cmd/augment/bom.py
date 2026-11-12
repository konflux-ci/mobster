"""
Abstract BOM augmenter.
"""

import argparse
import asyncio
import itertools
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Coroutine
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiofiles

from mobster.cmd.augment.handlers import CycloneDXVersion1, SPDXVersion2
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci import cosign
from mobster.oci.artifact import BOM
from mobster.release import Component, ReleaseId, ReleaseRepository, Snapshot
from mobster.sbom.detect import BOMFormat

LOGGER = logging.getLogger(__name__)


@dataclass
class BOMRefDetail:
    """
    Result of SBOM augmentation process.
    The SBOMs are not stored in-memory but in
    the filesystem to ease the load on memory.

    Attributes:
        reference: Reference to the image this attestation belongs to
        sbom_format: The format of the SBOM
        path: Path to the local SBOM file
    """

    reference: str
    sbom_format: BOMFormat
    path: Path


@dataclass
class AugmentConfig:
    """
    Configuration for SBOM augmentation.

    Attributes:
        cosign: Implementation of the fetch protocol for manipulating SBOMs
        verify: Use pubkey verification for attestations
        semaphore: asyncio semaphore to limit the number of concurrent operations
        output_dir: Path to directory to save the augmented SBOMs to
        release_id: ReleaseId to optionally inject into SBOMs
        cpes: List of string CPEs to add to the SBOM
    """

    cosign: cosign.SupportsFetch
    verify: bool
    semaphore: asyncio.Semaphore
    output_dir: Path
    release_id: ReleaseId | None = None
    cpes: list[str] = field(default_factory=list)


class BOMAugmenter(ABC):
    """
    Abstract class for augmenting BOMs.
    Requires overriding load_bom
    and potentially other methods.
    """

    @classmethod
    def get_sbom_to_filename_dict(cls, sboms: list[BOM]) -> dict[BOM, str]:
        """
        Get a dictionary mapping SBOMs to file names. Uses uuids as suffixes,
        ensuring no two SBOMs are written to the same file.

        Args:
            sboms: List of augmented SBOM objects

        Returns:
            A mapping of SBOMs to file names
        """

        sbom_to_filename: dict[BOM, str] = {}
        for sbom in sboms:
            while (
                filename := cls.get_randomized_sbom_filename(sbom)
            ) in sbom_to_filename.values():
                pass
            sbom_to_filename[sbom] = filename

        return sbom_to_filename

    @classmethod
    def get_randomized_sbom_filename(cls, sbom: BOM) -> str:
        """
        Get a filename for an SBOM. Uses a uuid suffix to try and deduplicate SBOM
        file names.

        Args:
            sbom: Augmented SBOM object

        Returns:
            File name with uuid suffix to save the SBOM to
        """
        suffix = uuid4().hex
        return f"{sbom.image.reference.replace('/', '-')}-{suffix}"

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

        handler = get_bom_handler(sbom)
        if handler:
            handler.update_sbom(
                repository,
                sbom.image,
                sbom.doc,
                cpes,
                release_id,
            )
            return True
        return False

    @abstractmethod
    async def load_bom(self, image: Image, config: AugmentConfig) -> BOM | None:
        """Load a fresh BOM, or return None when an optional BOM is unavailable."""

    async def update_bom(
        self,
        config: AugmentConfig,
        repository: ReleaseRepository,
        image: Image,
    ) -> BOMRefDetail | None:
        """
        Get an augmented SBOM of an image in a repository.

        Determines format of the SBOM and calls the correct handler.

        Args:
            config: Configuration for SBOM augmentation.
            repository: The repository the image is released to.
            image: Object representing an image or an index image being released.
        Returns:
            Detail of the augmented SBOM if it was successfully augmented,
            SkippedBOM.UNAVAILABLE if no optional BOM is available, or None on failure.
        """

        async with config.semaphore:
            try:
                sbom = await self.load_bom(image, config)
                if sbom is None:
                    return None
                if not self.update_bom_in_situ(
                    repository,
                    sbom,
                    config.cpes,
                    config.release_id,
                ):
                    raise SBOMError(f"Unsupported SBOM format for image {sbom.image}.")
                sbom.image = Image(
                    repository=repository.public_repo_url,
                    digest=sbom.image.digest,
                    arch=sbom.image.arch,
                )
                if repository.tags:
                    sbom.image.tag = repository.tags[0]
                path = config.output_dir / self.get_randomized_sbom_filename(sbom)
                await write_bom(sbom.doc, path)

                LOGGER.info(
                    "Successfully augmented SBOM for image %s "
                    "(released to %s and pushed to %s)",
                    sbom.image,
                    repository.public_repo_url,
                    repository.internal_repo_url,
                )
                return BOMRefDetail(
                    repository.internal_repo_url + "@" + sbom.image.digest,
                    sbom.format,
                    path,
                )
            except Exception:  # pylint: disable=broad-except
                # We catch all exceptions, because we're processing many SBOMs
                # concurrently and an uncaught exception would halt all concurrently
                # running updates.
                LOGGER.exception(
                    "Failed to augment SBOM for image %s (released to %s).",
                    image,
                    repository.public_repo_url,
                )
                return None

    async def augment_boms(
        self,
        config: AugmentConfig,
        snapshot: Snapshot,
    ) -> list[BOMRefDetail | None]:
        """
        Update component SBOMs with release-time information based on a Snapshot.

        Args:
            config: Configuration for SBOM augmentation.
            snapshot: An object representing a snapshot being released.

        Returns:
            True if all SBOMs were successfully augmented, False otherwise.
        """
        results = await asyncio.gather(
            *[
                self.update_component_boms(config, component)
                for component in snapshot.components
            ],
        )
        # Flatten the nested results
        return list(itertools.chain(*results))

    async def update_component_boms(
        self, config: AugmentConfig, component: Component
    ) -> list[BOMRefDetail | None]:
        """
        Update all component BOMs.
        Args:
            config: The Augmentation Configuration.
            component: The Component being augmented.

        Returns:
            Augmentation result reference details.
        """
        update_tasks: list[Coroutine[Any, Any, BOMRefDetail | None]] = []
        update_tasks.extend(
            self.update_bom(config, repo, component.image)
            for repo in component.release_repositories
        )

        if isinstance(component.image, IndexImage):
            for child in component.image.children:
                update_tasks.extend(
                    self.update_bom(config, repo, child)
                    for repo in component.release_repositories
                )
        return await asyncio.gather(*update_tasks)


def get_bom_handler(sbom: BOM) -> CycloneDXVersion1 | SPDXVersion2 | None:
    """
    Get the correct SBOM handler for the SBOM type.
    Args:
        sbom: The SBOM object.

    Returns:
        An SBOM handler or None if the SBOM format is unsupported.
    """
    for handler_class in CycloneDXVersion1, SPDXVersion2:
        if sbom.format in handler_class.supported_versions:
            return handler_class()
    return None


async def write_bom(sbom: Any, path: Path) -> None:
    """
    Write an SBOM doc dictionary to a file.
    """
    async with aiofiles.open(path, "w") as fp:
        await fp.write(json.dumps(sbom))


def get_augment_config_from_cli_args(args: argparse.Namespace) -> AugmentConfig:
    """
    Get augmentation configuration from CLI arguments.
    Args:
        args: The Argparse Namespace (parsed args).

    Returns:
        Loaded typed configuration object.
    """
    return AugmentConfig(
        cosign=cosign.StaticKeyFetcher(
            cosign.VerifyConfig(static_verify_key=args.verification_key)
        ),
        verify=args.verification_key is not None,
        semaphore=asyncio.Semaphore(args.concurrency),
        output_dir=args.output,
        release_id=args.release_id,
        cpes=args.cpes,
    )
