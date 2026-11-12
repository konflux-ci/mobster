"""
Module for Oras fetching command wrappers
"""

import tempfile

from mobster.image import Image
from mobster.oci import make_oci_auth_file
from mobster.oci.artifact import BOM
from mobster.utils import run_async_subprocess


class CBOMFetchError(Exception):
    """
    Exception raised when Oras fetching fails.
    """


class OrasClient:
    """
    Oras client class.
    """

    @staticmethod
    async def fetch_cbom(cbom_blob_url: str, image: Image) -> BOM:
        """
        Fetch CBOM with Oras.
        Args:
            cbom_blob_url: The digest-pinned CBOM blob URL.
            image: The Image this CBOM is associated with.

        Returns:
            The CBOM.
        """
        with tempfile.NamedTemporaryFile("w+b") as tmp:
            with make_oci_auth_file(cbom_blob_url) as authfile:
                command = [
                    "oras",
                    "blob",
                    "fetch",
                    cbom_blob_url,
                    "--output",
                    tmp.name,
                    "--registry-config",
                    str(authfile.absolute()),
                ]
                code, stdout, stderr = await run_async_subprocess(
                    command, retry_times=3
                )
                if code != 0:
                    raise CBOMFetchError(
                        f"Failed to fetch CBOM. Oras output: {stdout.decode()}, "
                        f"{stderr.decode()}"
                    )
            return BOM.from_cosign_output(tmp.read(), image)
