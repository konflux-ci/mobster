"""An image module for representing OCI images."""

import hashlib
import re
from dataclasses import dataclass

from packageurl import PackageURL


@dataclass
class Image:  # pylint: disable=too-many-instance-attributes
    """
    Dataclass representing an oci image.
    """

    repository: str
    name: str
    full_name: str
    digest: str
    tag: str
    arch: str | None
    domain: str | None = None
    digest_alg: str | None = None

    # Regular expression to validate OCI image references with digest
    # credit to https://regex101.com/r/nmSDPA/1)
    ARTIFACT_PATTERN = r"""
    ^
    (?P<repository>
      (?:(?P<domain>(?:(?:[\w-]+(?:\.[\w-]+)+)(?::\d+)?)|[\w]+:\d+)/)
      (?P<name>[a-z0-9_.-]+(?:/[a-z0-9_.-]+)*)
    )
    (?::(?P<tag>[\w][\w.-]{0,127}))?
    (?:@(?P<digest>
      (?P<digest_alg>[A-Za-z][A-Za-z0-9]*)(?:[+.-_][A-Za-z][A-Za-z0-9]*)*:
      (?P<digest_hash>[0-9a-fA-F]{32,})))
    $
    """

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
        full_name = "/".join(repository.split("/")[1:])
        _, name = repository.rsplit("/", 1)

        return Image(
            repository=repository,
            name=name,
            full_name=full_name,
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

        pattern = re.compile(Image.ARTIFACT_PATTERN, re.VERBOSE | re.MULTILINE)
        match = pattern.match(oci_reference)
        if not match:
            raise ValueError(f"Invalid OCI artifact reference format: {oci_reference}")
        full_name = match.group("name")
        name = full_name
        if "/" in full_name:
            name = name.split("/")[-1]
        return Image(
            repository=match.group("repository"),
            name=name,
            full_name=full_name,
            domain=match.group("domain"),
            digest=match.group("digest"),
            tag=match.group("tag"),
            arch=None,
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
