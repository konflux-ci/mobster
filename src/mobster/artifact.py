"""Artifact representation for the oci-copy task schema."""

import hashlib
import re
from dataclasses import dataclass

from packageurl import PackageURL


@dataclass
class Artifact:
    """
    Artifact represented by the oci-copy task schema
    """

    # https://github.com/konflux-ci/build-definitions/blob/main/task/oci-copy/0.1/README.md#oci-copyyaml-schema
    source: str
    filename: str
    type: str
    sha256sum: str

    @property
    def sanitized_filename(self) -> str:
        """
        Sanitize the filename by replacing non-alphanumeric characters with '-'.

        Returns:
            str: A sanitized version of the filename.
        """
        return re.sub(r"[^0-9a-zA-Z\.\-\+]", "-", self.filename)

    def purl(self) -> PackageURL:
        """
        A package URL representation of the artifact.

        Returns:
            PackageURL: A package URL object representing the artifact.
        """
        return PackageURL(
            type="generic",
            name=self.filename,
            qualifiers={
                "download_url": self.source,
                "checksum": f"sha256:{self.sha256sum}",
            },
        )

    def purl_str(self) -> str:
        """
        A package URL representation of the artifact in string format.
        Returns:
            str: Package URL string.
        """
        return self.purl().to_string()

    def propose_spdx_id(self) -> str:
        """
        Generate a proposed SPDX ID for the image.
        The ID is generated using the image name and a SHA-256 hash of the package URL.

        Returns:
            str: A proposed SPDX ID for the image.
        """
        purl_hex_digest = hashlib.sha256(self.purl_str().encode()).hexdigest()
        return f"SPDXRef-Package-{self.sanitized_filename}-{purl_hex_digest}"

    def propose_cyclonedx_bom_ref(self) -> str:
        """
        Generate a proposed CycloneDX BOM reference for the image.
        The reference is generated using the image name and a SHA-256 hash of the
        package URL.

        Returns:
            str: A proposed CycloneDX BOM reference for the image.
        """
        purl_hex_digest = hashlib.sha256(self.purl_str().encode()).hexdigest()
        return f"BomRef.{self.sanitized_filename}-{purl_hex_digest}"
