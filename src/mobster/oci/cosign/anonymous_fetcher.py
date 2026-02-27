"""Cosign fetch client without any secrets for verification"""

from mobster.image import Image
from mobster.oci.artifact import SBOM, Provenance02
from mobster.oci.cosign.protocol import SupportsFetch


class AnonymousFetcher(SupportsFetch):
    """
    Cosign fetch client with no secrets for verification
    """

    async def fetch_sbom(self, image: Image) -> SBOM:
        # TODO: ISV-6681: pylint: disable=fixme
        #  implement this and use in contextualization.
        #  may also want to add it to get_cosign.py after implementation
        raise NotImplementedError()

    async def fetch_latest_provenance(self, image: Image) -> Provenance02:
        # TODO: ISV-6681: pylint: disable=fixme
        #  implement or discard this
        raise NotImplementedError()
