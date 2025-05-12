"""An image module for representing OCI images."""

import hashlib
from dataclasses import dataclass

from packageurl import PackageURL


@dataclass
class Image:
    """
    Dataclass representing an oci image.
    """

    repository: str
    name: str
    digest: str
    tag: str
    arch: str | None

    @staticmethod
    def from_image_index_url_and_digest(
        image_tag_pullspec: str,
        image_digest: str,
        arch: str | None = None,
    ) -> "Image":
        """
        Create an Image object from the image URL and digest.

        Args:
            image_tag_pullspec (str): Image pullspec in the format
                <registry>/<repository>:<tag>
            image_digest (str): Image digest in the format sha256:<digest>
            arch (str | None, optional): Image architecure if present. Defaults to None.

        Returns:
            Image: A representation of the OCI image.
        """
        repository, tag = image_tag_pullspec.rsplit(":", 1)
        _, name = repository.rsplit("/", 1)

        return Image(
            repository=repository,
            name=name,
            digest=image_digest,
            tag=tag,
            arch=arch,
        )

    @property
    def digest_algo(self) -> str:
        """
        Get the algorithm used for the digest.

        Returns:
            str: An uppercase string representing the algorithm used for the digest.
        """
        algo, _ = self.digest.split(":")
        return algo.upper()

    @property
    def digest_hex_val(self) -> str:
        """
        A digest value in hex format.

        Returns:
            str: A hex string representing the digest value.
        """
        _, val = self.digest.split(":")
        return val

    def purl(self) -> str:
        """
        A package URL representation of the image in string format.

        Returns:
            str: Package URL string.
        """
        qualifiers = {"repository_url": self.repository}
        if self.arch is not None:
            qualifiers["arch"] = self.arch

        purl = PackageURL(
            type="oci",
            name=self.name,
            version=self.digest,
            qualifiers=qualifiers,
        ).to_string()

        return purl

    def propose_spdx_id(self) -> str:
        """
        Generate a proposed SPDX ID for the image.
        The ID is generated using the image name and a SHA-256 hash of the package URL.

        Returns:
            str: A proposed SPDX ID for the image.
        """
        purl_hex_digest = hashlib.sha256(self.purl().encode()).hexdigest()
        return f"SPDXRef-image-{self.name}-{purl_hex_digest}"
