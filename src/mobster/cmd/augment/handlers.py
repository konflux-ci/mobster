"""
This module is used to augment release-time SBOMs.
"""

import logging
from typing import Any

from packageurl import PackageURL

from mobster import get_mobster_version
from mobster.error import SBOMError
from mobster.image import Image, IndexImage
from mobster.oci.artifact import SBOMFormat
from mobster.release import Component
from mobster.sbom import cyclonedx

logger = logging.getLogger(__name__)


class SPDXPackage:
    """
    Wrapper class for easier SPDX package manipulation.
    """

    def __init__(self, package: Any) -> None:
        self.package = package

    @property
    def external_refs(self) -> Any:
        """
        Get the externalRefs field of the package.
        """
        return self.package.get("externalRefs", [])

    @external_refs.setter
    def external_refs(self, value: list[Any]) -> None:
        """
        Set the externalRefs field.
        """
        self.package["externalRefs"] = value

    @property
    def spdxid(self) -> Any:
        """
        Return the SPDXID field value of the package.
        """
        return self.package.get("SPDXID", "UNKNOWN")

    @property
    def checksums(self) -> Any:
        """
        Get the checksums field of the package.
        """
        return self.package.get("checksums", [])

    @property
    def sha256_checksum(self) -> Any | None:
        """
        Extracts a sha256 checksum from an SPDX package. Returns None if no such
        checksum is found.
        """
        checksums = self.checksums
        if checksums is None:
            return None

        for checksum in checksums:
            if checksum.get("algorithm") == "SHA256":
                return checksum.get("checksumValue")

        return None

    def update_external_refs(
        self,
        image: Image,
        repository: str,
        tags: list[str],
        arch: str | None = None,
    ) -> None:
        """
        Update the external refs of an SPDX package by creating new OCI PURL
        references and stripping all old OCI PURL references. Other types of
        externalRefs are preserved.
        """
        new_oci_refs = SPDXPackage._get_updated_oci_purl_external_refs(
            image,
            repository,
            tags,
            arch=arch,
        )

        self._strip_oci_purls_external_refs()
        self.external_refs[:0] = new_oci_refs

    def _strip_oci_purls_external_refs(self) -> None:
        """
        Remove all OCI purl externalRefs from a package.
        """

        def is_oci_purl_ref(ref: Any) -> bool:
            ptype = ref.get("referenceType")
            if ptype != "purl":
                return False
            purl_str = ref.get("referenceLocator")
            if purl_str is None:
                return False

            purl = PackageURL.from_string(purl_str)
            return purl.type == "oci"

        new_external_refs = [
            ref for ref in self.external_refs if not is_oci_purl_ref(ref)
        ]
        self.external_refs = new_external_refs

    @staticmethod
    def _get_updated_oci_purl_external_refs(
        image: Image, repository: str, tags: list[str], arch: str | None = None
    ) -> list[Any]:
        """
        Gets new oci purl externalRefs value based on input information.
        """
        purls = (construct_purl(image, repository, tag=tag, arch=arch) for tag in tags)
        return [SPDXPackage._make_purl_ref(purl) for purl in purls]

    @staticmethod
    def _make_purl_ref(purl: str) -> dict[str, str]:
        """
        Create an SPDX externalRefs field from a PackageURL.
        """
        return {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }


class SPDXVersion2:  # pylint: disable=too-few-public-methods
    """
    Class containing methods for SPDX v2.x SBOM manipulation.
    """

    supported_versions = [
        SBOMFormat.SPDX_2_0,
        SBOMFormat.SPDX_2_1,
        SBOMFormat.SPDX_2_2,
        SBOMFormat.SPDX_2_2_1,
        SBOMFormat.SPDX_2_2_2,
        SBOMFormat.SPDX_2_3,
    ]

    @classmethod
    def _find_purl_in_refs(cls, package: SPDXPackage, digest: str) -> Any | None:
        """
        Tries to find a purl in the externalRefs of a package the version of
        which matches the passed digest.
        """
        for ref in filter(
            lambda rf: rf["referenceType"] == "purl", package.external_refs
        ):
            purl = ref["referenceLocator"]
            if digest == get_purl_digest(purl):
                return purl

        return None

    @classmethod
    def _find_image_package(cls, sbom: Any, image: Image) -> SPDXPackage | None:
        """
        Find the SPDX package for an image, based on the package checksum.
        """
        for package in map(SPDXPackage, sbom.get("packages", [])):
            if without_sha_header(image.digest) == package.sha256_checksum:
                return package

        return None

    @classmethod
    def _augment_creation_info(cls, creation_info: Any) -> None:
        """
        Add Mobster version information to creationInfo.
        """
        version = get_mobster_version()
        creator = f"Tool: Mobster-{version}"
        if creator not in creation_info["creators"]:
            creation_info["creators"].append(creator)

    @classmethod
    def _update_index_image_sbom(
        cls, component: Component, index: IndexImage, sbom: Any
    ) -> None:
        """
        Update the SBOM of an index image in a repository.
        """
        sbom["name"] = f"{component.repository}@{index.digest}"

        index_package = cls._find_image_package(sbom, index)
        if not index_package:
            raise SBOMError(f"Could not find SPDX package for index {index}")

        index_package.update_external_refs(
            index,
            component.repository,
            component.tags,
        )

        for image in index.children:
            package = cls._find_image_package(sbom, image)
            if package is None:
                logger.warning("Could not find SPDX package for %s.", image.digest)
                continue

            original_purl = cls._find_purl_in_refs(package, image.digest)
            if original_purl is None:
                logger.warning(
                    "Could not find OCI PURL for %s in package %s for index %s.",
                    image,
                    package.spdxid,
                    index,
                )
                continue

            arch = get_purl_arch(original_purl)
            package.update_external_refs(
                image,
                component.repository,
                component.tags,
                arch=arch,
            )

    @classmethod
    def _update_image_sbom(cls, component: Component, image: Image, sbom: Any) -> None:
        """
        Update the SBOM of single-arch image in a repository.
        """
        sbom["name"] = f"{component.repository}@{image.digest}"

        image_package = cls._find_image_package(sbom, image)
        if not image_package:
            raise SBOMError(
                f"Could not find SPDX package in SBOM for image {image.digest}"
            )

        image_package.update_external_refs(
            image,
            component.repository,
            component.tags,
        )

    def update_sbom(self, component: Component, image: Image, sbom: Any) -> None:
        """
        Update a build-time SBOM with release-time data.
        """
        self._augment_creation_info(sbom["creationInfo"])
        if isinstance(image, IndexImage):
            SPDXVersion2._update_index_image_sbom(component, image, sbom)
        elif isinstance(image, Image):
            SPDXVersion2._update_image_sbom(component, image, sbom)


class CycloneDXVersion1:  # pylint: disable=too-few-public-methods
    """
    This class contains methods to update CycloneDX build-time SBOMs.
    """

    supported_versions = [
        SBOMFormat.CDX_V1_4,
        SBOMFormat.CDX_V1_5,
        SBOMFormat.CDX_V1_6,
    ]

    def update_sbom(self, component: Component, image: Image, sbom: Any) -> None:
        """
        Update an SBOM for an image based on a component.
        """
        if isinstance(image, IndexImage):
            raise ValueError("CDX update SBOM does not support index images.")

        self._bump_version(sbom)
        self._update_metadata_component(component, image, sbom)

        for cdx_component in sbom.get("components", []):
            if cdx_component.get("type") != "container":
                continue

            purl = cdx_component.get("purl")
            if purl is None or get_purl_digest(purl) != image.digest:
                continue

            self._update_container_component(
                component, image, cdx_component, update_tags=True
            )

    def _bump_version(self, sbom: Any) -> None:
        """
        Bump the CDX version to 1.6, so we can populate the fields relevant to
        tags. This is legal, because CycloneDX v1.X is forward-compatible (all
        1.4 and 1.5 boms are valid 1.6 boms).
        """
        # This is here to make sure an error is raised if this class is
        # updated for CDX 1.7.
        if sbom["specVersion"] not in ["1.4", "1.5", "1.6"]:
            raise SBOMError("Attempted to downgrade an SBOM.")

        logger.debug("Bumping CycloneDX version to 1.6")
        sbom["$schema"] = "http://cyclonedx.org/schema/bom-1.6.schema.json"
        sbom["specVersion"] = "1.6"

    def _update_component_purl_identity(
        self,
        kflx_component: Component,
        image: Image,
        arch: str | None,
        cdx_component: Any,
    ) -> None:
        if len(kflx_component.tags) <= 1:
            return

        new_identity = []
        for tag in kflx_component.tags:
            purl = construct_purl(image, kflx_component.repository, arch=arch, tag=tag)
            new_identity.append({"field": "purl", "concludedValue": purl})

        if cdx_component.get("evidence") is None:
            cdx_component["evidence"] = {}

        evidence = cdx_component["evidence"]
        identity = evidence.get("identity", [])

        # The identity can either be an array or a single object. In both cases
        # we preserve the original identity.
        if isinstance(identity, list):
            identity.extend(new_identity)
            evidence["identity"] = identity
        else:
            evidence["identity"] = [identity, *new_identity]

    def _update_container_component(
        self,
        kflx_component: Component,
        image: Image,
        cdx_component: Any,
        update_tags: bool,
    ) -> None:
        purl = cdx_component.get("purl")
        if not purl:
            return

        arch = get_purl_arch(purl)
        tag = kflx_component.tags[0] if kflx_component.tags else None
        new_purl = construct_purl(image, kflx_component.repository, arch=arch, tag=tag)
        cdx_component["purl"] = new_purl

        if update_tags:
            self._update_component_purl_identity(
                kflx_component, image, arch, cdx_component
            )

    def _augment_metadata_tools_components(self, metadata: Any) -> None:
        """
        Add Mobster version information to metadata.tools.components
        """
        if "tools" not in metadata:
            metadata["tools"] = {"components": []}

        components = metadata["tools"]["components"]
        if not self._has_current_mobster_version(components):
            components.append(cyclonedx.get_tools_component_dict())

    def _has_current_mobster_version(self, components: list[Any]) -> bool:
        """
        Check whether a list of components contains a component with name
        "Mobster" and the current Mobster version.
        """
        return ("Mobster", get_mobster_version()) in [
            (c["name"], c.get("version")) for c in components
        ]

    def _update_metadata_component(
        self, kflx_component: Component, image: Image, sbom: Any
    ) -> None:
        component = sbom.get("metadata", {}).get("component", {})
        self._update_container_component(
            kflx_component, image, component, update_tags=False
        )

        if "metadata" in sbom:
            sbom["metadata"]["component"] = component
        else:
            metadata = {"component": component}
            sbom["metadata"] = metadata

        self._augment_metadata_tools_components(sbom["metadata"])


def construct_purl(
    image: Image,
    release_repository: str,
    arch: str | None = None,
    tag: str | None = None,
) -> str:
    """
    Construct an OCI PackageURL string from image data.

    Args:
        image (Image): The image being released
        release_repository (str): The repository the image is being released to
        arch (str | None): Architecture of the image if specified
        tag (str | None): Tag of the image if specified
    """
    repo_name = release_repository.split("/")[-1]

    optional_qualifiers = {}
    if arch is not None:
        optional_qualifiers["arch"] = arch

    if tag is not None:
        optional_qualifiers["tag"] = tag

    return PackageURL(
        type="oci",
        name=repo_name,
        version=image.digest,
        qualifiers={"repository_url": release_repository, **optional_qualifiers},
    ).to_string()


def get_purl_arch(purl_str: str) -> str | None:
    """
    Get the arch qualifier from a PackageURL.
    """
    purl = PackageURL.from_string(purl_str)
    if isinstance(purl.qualifiers, dict):
        return purl.qualifiers.get("arch")

    logger.warning("Parsed qualifiers from purl %s are not a dictionary.", purl_str)
    return None


def get_purl_digest(purl_str: str) -> str:
    """
    Get the image digest from a PackageURL.
    """
    purl = PackageURL.from_string(purl_str)
    if purl.version is None:
        raise SBOMError(f"SBOM contains invalid OCI Purl: {purl_str}")
    return purl.version


def without_sha_header(digest: str) -> str:
    """
    Returns a digest without the "sha256:" header.
    """
    return digest.removeprefix("sha256:")
