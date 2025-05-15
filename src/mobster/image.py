"""An image module for representing OCI images."""

import hashlib
from dataclasses import dataclass, field

from packageurl import PackageURL

from mobster.error import SBOMError
from mobster.oci import get_image_manifest


@dataclass
class Image:
    """
    Dataclass representing an oci image.
    """

    repository: str
    digest: str
    tag: str | None = None
    arch: str | None = None

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
        return Image(
            repository=repository,
            digest=image_digest,
            tag=tag,
            arch=arch,
        )

    @staticmethod
    async def from_repository_digest(repository: str, digest: str) -> "Image":
        """
        # TODO: make this description more accurate
        Creates an Image or IndexImage object based on an image reference. Performs
        a registry call for index images, to parse all their child digests.
        """
        image = Image(repository=repository, digest=digest)
        manifest = await get_image_manifest(image.reference)
        media_type = manifest["mediaType"]

        if media_type in {
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        }:
            return image

        if media_type in {
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        }:
            children = []
            for submanifest in manifest["manifests"]:
                child_digest = submanifest["digest"]
                children.append(Image(repository=repository, digest=child_digest))

            return IndexImage(repository=repository, digest=digest, children=children)

        raise SBOMError(f"Unsupported mediaType: {media_type}")

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
    def reference(self) -> str:
        """
        Full reference to the image using its digest.

        Returns:
            str: String containing the reference.

        Example:
            >>> img.reference
            quay.io/repo/name@sha256:7a833e39b0a1eee003839841cd125b7e14eff8473a6518d83c38dbe644cfe62a
        """
        return f"{self.repository}@{self.digest}"

    @property
    def digest_hex_val(self) -> str:
        """
        A digest value in hex format.

        Returns:
            str: A hex string representing the digest value.
        """
        _, val = self.digest.split(":")
        return val

    @property
    def name(self) -> str:
        _, name = self.repository.rsplit("/", 1)
        return name

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

    def __str__(self) -> str:
        return self.reference


@dataclass
class IndexImage(Image):
    """
    Object representing an index image in a repository. It also contains child
    images.
    """

    children: list[Image] = field(default_factory=list)
