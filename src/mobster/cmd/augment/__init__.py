"""A module for augmenting SBOM documents."""

import asyncio
import json
from pathlib import Path
from typing import Any

import aiofiles

from mobster.cmd.augment.handlers import CycloneDXVersion1, SPDXVersion2
from mobster.cmd.base import Command
from mobster.error import SBOMError, SBOMVerificationError
from mobster.image import Image, IndexImage
from mobster.logging import get_mobster_logger
from mobster.oci.artifact import SBOM
from mobster.oci.cosign import Cosign, CosignClient
from mobster.release import Component, Snapshot, make_snapshot

LOGGER = get_mobster_logger()


class AugmentComponentCommand(Command):
    """
    Command to augment a component.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    async def execute(self) -> Any:
        """
        Execute the command to augment a component.
        """
        # Placeholder for the actual implementation
        LOGGER.debug("Augmenting component image SBOM")

    async def save(self) -> None:
        """
        Save the command state.
        """
        # Placeholder for the actual implementation


class AugmentSnapshotCommand(Command):
    """
    Command to augment all components in a snapshot.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    async def execute(self) -> Any:
        """
        Execute the command to augment a component.
        """
        snapshot = await make_snapshot(self.cli_args.snapshot)

        verify = self.cli_args.verification_key is not None
        cosign = CosignClient(self.cli_args.verification_key)

        await update_sboms(snapshot, self.cli_args.output, cosign, verify)

    async def save(self) -> None:
        """
        Save the command state.
        """
        pass


async def verify_sbom(sbom: SBOM, image: Image, cosign: Cosign) -> None:
    """
    Verify that the sha256 digest of the specified SBOM matches the value of
    SBOM_BLOB_URL in the provenance for the supplied image. Cosign is
    used to fetch the provenance. If it doesn't match, an SBOMVerificationError
    is raised.
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
    """
    sbom = await cosign.fetch_sbom(image)
    if verify:
        await verify_sbom(sbom, image, cosign)
    return sbom


async def write_sbom(sbom: Any, path: Path) -> None:
    """
    Write an SBOM doc to a file.
    """
    async with aiofiles.open(path, "w") as fp:
        await fp.write(json.dumps(sbom))


def update_sbom_in_situ(component: Component, image: Image, sbom: SBOM) -> bool:
    """
    Determine the matching SBOM handler and update the SBOM with release-time
    information in situ.

    Args:
        component (Component): The component the image belongs to.
        image (IndexImage | Image): Object representing an image or an index
                                    image being released.
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
    component: Component, image: Image, destination: Path, cosign: Cosign, verify: bool
) -> None:
    """
    Update an SBOM of an image in a repository and save it to a directory.
    Determines format of the SBOM and calls the correct handler or throws
    SBOMError if the format of the SBOM is unsupported.

    Args:
        component (Component): The component the image belongs to.
        image (IndexImage | Image): Object representing an image or an index
                                    image being released.
        destination (Path): Path to the directory to save the SBOMs to.
    """

    try:
        sbom = await load_sbom(image, cosign, verify)
        if not update_sbom_in_situ(component, image, sbom):
            raise SBOMError(f"Unsupported SBOM format for image {image}.")

        await write_sbom(sbom.doc, destination.joinpath(image.digest))
        LOGGER.info("Successfully enriched SBOM for image %s", image)
    except (SBOMError, ValueError):
        LOGGER.exception("Failed to enrich SBOM for image %s.", image)
        raise


async def update_component_sboms(
    component: Component, destination: Path, cosign: Cosign, verify: bool
) -> None:
    """
    Update SBOMs for a component and save them to a directory.

    Handles multiarch images as well.

    Args:
        component (Component): Object representing a component being released.
        destination (Path): Path to the directory to save the SBOMs to.
    """
    if isinstance(component.image, IndexImage):
        # If the image of a component is a multiarch image, we update the SBOMs
        # for both the index image and the child single arch images.
        index = component.image
        update_tasks = [
            update_sbom(component, index, destination, cosign, verify),
        ]
        for child in index.children:
            update_tasks.append(
                update_sbom(component, child, destination, cosign, verify)
            )

        results = await asyncio.gather(*update_tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, BaseException):
                raise res
        return

    # Single arch image
    await update_sbom(component, component.image, destination, cosign, verify)


async def update_sboms(
    snapshot: Snapshot, destination: Path, cosign: Cosign, verify: bool
) -> None:
    """
    Update component SBOMs with release-time information based on a Snapshot and
    save them to a directory.

    Args:
        Snapshot: A object representing a snapshot being released.
        destination (Path): Path to the directory to save the SBOMs to.
    """
    # use return_exceptions=True to avoid crashing non-finished tasks if one
    # task raises an exception.
    results = await asyncio.gather(
        *[
            update_component_sboms(component, destination, cosign, verify)
            for component in snapshot.components
        ],
        return_exceptions=True,
    )
    # Python 3.11 ExceptionGroup would be nice here, so we can re-raise all the
    # exceptions that were raised and not just one. Consider when migrating to
    # mobster.
    for res in results:
        if isinstance(res, BaseException):
            raise res
