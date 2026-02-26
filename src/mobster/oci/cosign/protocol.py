"""This module contains the Cosign protocol definition."""

import typing
from pathlib import Path

from mobster.image import Image
from mobster.oci.artifact import SBOM, Provenance02, SBOMFormat


class SupportsFetch(typing.Protocol):  # pragma: nocover
    """
    Definition of a Cosign fetch protocol.
    """

    async def fetch_sbom(self, image: Image) -> SBOM:
        """
        Fetch the attached SBOM for an image.
        """
        raise NotImplementedError()

    async def fetch_latest_provenance(self, image: Image) -> Provenance02:
        """
        Fetch the latest provenance for an image.
        """
        raise NotImplementedError()


class SupportsSign(typing.Protocol):
    """
    Definition of a Cosign sign protocol.
    """

    # pylint: disable=too-few-public-methods

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: SBOMFormat,
    ) -> None:
        """
        Use cosign to attach an SBOM to the registry. This is the new
        way of attaching an SBOM to an image.
        Args:
            sbom_path: The path to the SBOM file
            image_ref: The reference of the image
            sbom_format: The format of the SBOM to attest
        """
        raise NotImplementedError()
