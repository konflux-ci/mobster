"""A module for augmenting SBOM documents."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import aiofiles

from mobster.cmd.augment.handlers import CycloneDXVersion1, SPDXVersion2
from mobster.cmd.base import Command
from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOM
from mobster.oci.cosign import Cosign, CosignClient
from mobster.release import Component, Snapshot, make_snapshot

LOGGER = logging.getLogger(__name__)


class AugmentImageCommand(Command):
    """
    Command for augmenting OCI image SBOMs.

    Attributes:
        sbom_update_ok (bool): True if all SBOMs updated successfully
        sboms (list[SBOM]): List of updated SBOMs
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.sboms: list[SBOM] = []

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

        snapshot = await make_snapshot(self.cli_args.snapshot, digest)
        verify = self.cli_args.verification_key is not None
        cosign = CosignClient(self.cli_args.verification_key)
        concurrency_limit = self.cli_args.concurrency

        ok, self.sboms = await update_sboms(snapshot, cosign, verify, concurrency_limit)
        if not ok:
            self.exit_code = 1

    async def save(self) -> None:
        """
        Write all updated sboms to the output.
        """
        destination = Path(self.cli_args.output)

        tasks = [
            write_sbom(sbom.doc, destination.joinpath(sbom.reference.split("@", 1)[1]))
            for sbom in self.sboms
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for sbom, res in zip(self.sboms, results, strict=False):
            if isinstance(res, BaseException):
                self.exit_code = 1
                LOGGER.error("Error while writing SBOM %s: %s", sbom.reference, res)


async def verify_sbom(sbom: SBOM, image: Image, cosign: Cosign) -> None:
    """
    Verify that the sha256 digest of the specified SBOM matches the value of
    SBOM_BLOB_URL in the provenance for the supplied image. Cosign is used to
    fetch the provenance. If it doesn't match, an SBOMVerificationError is
    raised.

    Args:
        sbom (SBOM): the sbom to verify
        image (Image): image to verify the sbom for
        cosign (Cosign): implementation of the Cosign protocol
    """

    prov = await cosign.fetch_latest_provenance(image)
    prov_sbom_digest = prov.get_sbom_digest(image)

    if prov_sbom_digest != sbom.digest:
        raise SBOMVerificationError(
            prov_sbom_digest,
            sbom.digest,
        )


async def load_sbom(image: Image, cosign: Cosign, verify: bool) -> SBOM:
    """
    Download and parse the sbom for the image reference and verify that its digest
    matches that in the image provenance.

    Args:
        image (Image): image to load the sbom for
        cosign (Cosign): implementation of the Cosign protocol
        verify (bool): True if the SBOM's digest should be verified via the
            provenance of the image
    """
    sbom = await cosign.fetch_sbom(image)
    if verify:
        await verify_sbom(sbom, image, cosign)
    return sbom


async def write_sbom(sbom: Any, path: Path) -> None:
    """
    Write an SBOM doc dictionary to a file.
    """
    async with aiofiles.open(path, "w") as fp:
        await fp.write(json.dumps(sbom))


def update_sbom_in_situ(component: Component, image: Image, sbom: SBOM) -> bool:
    """
    Determine the matching SBOM handler and update the SBOM with release-time
    information in situ.

    Args:
        component (Component): The component the image belongs to.
        image (Image): Object representing an image being released.
        sbom (dict): SBOM parsed as dictionary.
    """

    if sbom.format in SPDXVersion2.supported_versions:
        SPDXVersion2().update_sbom(component, image, sbom.doc)
        return True

    # The CDX handler does not support updating SBOMs for index images, as those
    # are generated only as SPDX in Konflux.
    if sbom.format in CycloneDXVersion1.supported_versions and not isinstance(
        image, IndexImage
    ):
        CycloneDXVersion1().update_sbom(component, image, sbom.doc)
        return True

    return False


async def update_sbom(
    component: Component,
    image: Image,
    cosign: Cosign,
    verify: bool,
    semaphore: asyncio.Semaphore,
) -> SBOM | None:
    """Get an augmented SBOM of an image in a repository.

    Determines format of the SBOM and calls the correct handler or throws
    SBOMError if the format of the SBOM is unsupported.

    Args:
        component: The component the image belongs to.
        image: Object representing an image or an index image being released.
        cosign: Cosign client for verification.
        verify: Whether to verify SBOM digest via image provenance.
        semaphore: Concurrency control semaphore.

    Returns:
        An augmented SBOM if it can be enriched, None if enrichment fails.
    """

    async with semaphore:
        try:
            sbom = await load_sbom(image, cosign, verify)
            if not update_sbom_in_situ(component, image, sbom):
                raise SBOMError(f"Unsupported SBOM format for image {image}.")
            LOGGER.info("Successfully enriched SBOM for image %s", image)
            return sbom
        except Exception:  # pylint: disable=broad-except
            # We catch all exceptions, because we're processing many SBOMs
            # concurrently and an uncaught exception would halt all concurrently
            # running updates.
            LOGGER.exception("Failed to enrich SBOM for image %s.", image)
            return None


async def update_component_sboms(
    component: Component, cosign: Cosign, verify: bool, semaphore: asyncio.Semaphore
) -> tuple[bool, list[SBOM]]:
    """
    Update SBOMs for a component.

    Handles multiarch images as well.

    Args:
        component (Component): Object representing a component being released.
        cosign (Cosign): implementation of the Cosign protocol
        verify (bool): True if the SBOM's digest should be verified via the
            provenance of the image

    Returns:
        Tuple where the first value specifies whether all SBOMs were augmented
        successfully and the second value is the list of augmented SBOMs.
    """
    if isinstance(component.image, IndexImage):
        # If the image of a component is a multiarch image, we update the SBOMs
        # for both the index image and the child single arch images.
        index = component.image
        update_tasks = [
            update_sbom(component, index, cosign, verify, semaphore),
        ]
        for child in index.children:
            update_tasks.append(
                update_sbom(component, child, cosign, verify, semaphore)
            )

        results = await asyncio.gather(*update_tasks)
    else:
        # Single arch image
        results = [
            await update_sbom(component, component.image, cosign, verify, semaphore)
        ]

    status: bool = all(results)
    return status, list(filter(None, results))


async def update_sboms(
    snapshot: Snapshot, cosign: Cosign, verify: bool, concurrency_limit: int
) -> tuple[bool, list[SBOM]]:
    """
    Update component SBOMs with release-time information based on a Snapshot.

    Args:
        snapshot (Snapshot): an object representing a snapshot being released.
        cosign (Cosign): implementation of the Cosign protocol
        verify (bool): True if the SBOM's digest should be verified via the
            provenance of the image
        concurrency_limit: concurrency limit for SBOM augmentation
    """
    semaphore = asyncio.Semaphore(concurrency_limit)

    results = await asyncio.gather(
        *[
            update_component_sboms(component, cosign, verify, semaphore)
            for component in snapshot.components
        ],
    )

    all_ok = True
    all_sboms = []
    for ok, sboms in results:
        if not ok:
            all_ok = False
        all_sboms.extend(sboms)

    return all_ok, all_sboms
