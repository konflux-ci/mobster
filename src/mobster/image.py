"""An image module for representing OCI images."""

import hashlib
import re
from dataclasses import dataclass, field

from packageurl import PackageURL

from mobster.error import SBOMError
from mobster.oci import get_image_manifest

# Regular expression to validate OCI image references with digest
# credit to https://regex101.com/r/nmsdpa/1)
_REPOSITORY_REGEX_STR = r"""
(?P<repository>
  (?:(?P<domain>(?:(?:[\w-]+(?:\.[\w-]+)+)(?::\d+)?)|[\w]+:\d+)/)
  (?P<name>[a-z0-9_.-]+(?:/[a-z0-9_.-]+)*)
)
"""
_TAG_REGEX_STR = r"(?::(?P<tag>[\w][\w.-]{0,127}))?"
_DIGEST_REGEX_STR = r"""
(?:@(?P<digest>
      (?P<digest_alg>[A-Za-z][A-Za-z0-9]*)(?:[+.-_][A-Za-z][A-Za-z0-9]*)*:
      (?P<digest_hash>[0-9a-fA-F]{32,}))
)
"""
ARTIFACT_PATTERN = re.compile(
    f"^{_REPOSITORY_REGEX_STR}{_TAG_REGEX_STR}{_DIGEST_REGEX_STR}$",
    re.VERBOSE | re.MULTILINE,
)
PULLSPEC_PATTERN = re.compile(
    f"^{_REPOSITORY_REGEX_STR}{_TAG_REGEX_STR}$", re.VERBOSE | re.MULTILINE
)


@dataclass
class Image:  # pylint: disable=too-many-instance-attributes
    """
    Dataclass representing an oci image.

    Attributes:
        repository (str): OCI repository.
        digest (str): sha256 digest of the image.
        tag (str | None): Image tag.
        arch (str | None): Image architecture
    """

    repository: str
    digest: str
    tag: str | None = None
    arch: str | None = None
    domain: str | None = None
    digest_alg: str | None = None

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
    def from_oci_artifact_reference(
        oci_reference: str,
    ) -> "Image":
        """
        Create an instance of the Image class from the image URL and digest.

        Args:
            oci_reference (str): The OCI artifact reference.

        Returns:
            OCI_Artifact: An instance of the Image class representing the artifact
            reference
        """
        match = ARTIFACT_PATTERN.match(oci_reference)
        if not match:
            raise ValueError(f"Invalid OCI artifact reference format: {oci_reference}")
        full_name = match.group("name")
        name = full_name
        if "/" in full_name:
            name = name.split("/")[-1]
        return Image(
            repository=match.group("repository"),
            domain=match.group("domain"),
            digest=match.group("digest"),
            tag=match.group("tag"),
            arch=None,
        )

    @staticmethod
    async def from_repository_digest_manifest(repository: str, digest: str) -> "Image":
        """
        Creates an Image or IndexImage object based on an image repository and
        digest. Performs a registry call for index images, to parse all their
        child digests.

        Args:
            repository (str): Image repository
            digest (str): Image digest

        Returns:
            Image | IndexImage: The image object parsed from a manifest
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
            quay.io/repo/name@sha256:7a833e39b0a1eee003839841cd125b7e14....
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
        """
        Name of the image.

        Example:
            >>> image("quay.io/org/apache", "sha256:deadbeef").name
            "apache"
        """
        return self.repository.rsplit("/", 1)[-1]

    def purl(self) -> PackageURL:
        """
        A package URL representation of the image in string format.

        Returns:
            PackageURL: Package URL.
        """
        qualifiers = {"repository_url": self.repository}
        if self.arch is not None:
            qualifiers["arch"] = self.arch

        purl = PackageURL(
            type="oci",
            name=self.name,
            version=self.digest,
            qualifiers=qualifiers,
        )

        return purl

    def purl_str(self) -> str:
        """
        A package URL representation of the image in string format.

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
        return f"SPDXRef-image-{self.name}-{purl_hex_digest}"

    def propose_cyclonedx_bom_ref(self) -> str:
        """
        Generate a proposed CycloneDX BOM reference for the image.
        The reference is generated using the image name and a SHA-256 hash of the
        package URL.

        Returns:
            str: A proposed CycloneDX BOM reference for the image.
        """
        purl_hex_digest = hashlib.sha256(self.purl_str().encode()).hexdigest()
        return f"BomRef.{self.name}-{purl_hex_digest}"

    def propose_sbom_name(self) -> str:
        """
        Generate a proposed SBOM name for the image.
        The name is generated using the image repository and a SHA-256 hash of the
        package URL.

        Returns:
            str: A proposed SBOM name for the image.
        """
        return f"{self.repository}@{self.digest}"

    def __str__(self) -> str:
        return self.reference


@dataclass
class IndexImage(Image):
    """
    Object representing an index image in a repository. It also contains child
    images.
    """

    children: list[Image] = field(default_factory=list)
