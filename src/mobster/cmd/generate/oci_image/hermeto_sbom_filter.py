"""A module for filtering an SBOM produced by Hermeto by architecture."""

import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

LOGGER = logging.getLogger(__name__)


def _extract_purl_from_external_refs(external_refs: list[dict[str, str]]) -> str:
    """Extract the referenceLocator string (purl) from a externalRefs dict."""
    purl_ref = next(
        (ref for ref in external_refs if ref.get("referenceType") == "purl"),
        None,
    )

    if not purl_ref:
        return ""

    return purl_ref.get("referenceLocator", "")


def _extract_arch_and_checksum_from_purl(purl: str) -> tuple[str | None, str | None]:
    parsed = urlparse(purl)
    query_params = parse_qs(parsed.query)

    arch = query_params.get("arch", [None])[0]
    checksum = query_params.get("checksum", [None])[0]

    return arch, checksum


def _filter_spdx_packages(
    packages: list[dict[str, Any]], target_arch: str
) -> tuple[list[dict[str, Any]], set[Any]]:
    """
    Filter RPM packages based on a target architecture.

    All packages that are not of type 'pkg:rpm' or that do not contain a purl will
    be kept.

    Args:
        packages: A list of SPDX packcages
        target_arch: The architecture to filter by

    Returns:
        tuple[
            dict[str, Any]: The filtered packages
            set[str]: A set containing the SPDXIDs of packages that were removed
        ]
    """
    filtered_packages = []
    removed_ids = set()
    noarch_checksums = set()

    for package in packages:
        external_refs = package.get("externalRefs", [])
        purl = _extract_purl_from_external_refs(external_refs)

        # only filter out packages that have a purl and are of type 'pkg:rpm'
        if not purl or not purl.startswith("pkg:rpm"):
            filtered_packages.append(package)
            continue

        arch, checksum = _extract_arch_and_checksum_from_purl(purl)

        if arch in {"noarch", target_arch}:
            if not checksum:
                filtered_packages.append(package)
            elif checksum not in noarch_checksums:
                filtered_packages.append(package)
                noarch_checksums.add(checksum)
            else:
                LOGGER.debug(
                    "Removing duplicate noarch package %s@%s (checksum: %s)",
                    package.get("name"),
                    package.get("version"),
                    checksum,
                )
                removed_ids.add(package.get("SPDXID"))
        else:
            LOGGER.debug(
                "Removing package %s with arch=%s (target: %s)",
                package.get("name"),
                arch,
                target_arch,
            )
            removed_ids.add(package.get("SPDXID"))

    return filtered_packages, removed_ids


def _filter_spdx_relationships(
    relationships: list[dict[str, str]],
    removed_ids: set[Any],
) -> list[dict[str, str]]:
    if not removed_ids:
        return relationships

    return [
        rel
        for rel in relationships
        if rel.get("spdxElementId") not in removed_ids
        and rel.get("relatedSpdxElement") not in removed_ids
    ]


def _filter_spdx_sbom_by_arch(
    sbom_dict: dict[str, Any], target_arch: str
) -> dict[str, Any]:
    """
    Filter the RPM packages based on a target architecture.

    Args:
        sbom_dict: The SBOM dictionary
        target_arch: The architecture to filter by (e.g., "x86_64", "aarch64")

    Returns:
        dict[str, Any]: The filtered SBOM dictionary

    Raises:
        ValueError: If target_arch evaluates to false or
        if the SBOM format is not recognized
    """
    LOGGER.info("Filtering SPDX SBOM by architecture: %s", target_arch)

    packages = sbom_dict.get("packages", [])
    if not packages:
        LOGGER.warning("No packages found in SBOM")
        return sbom_dict

    filtered_packages, removed_ids = _filter_spdx_packages(packages, target_arch)
    filtered_relationships = _filter_spdx_relationships(
        sbom_dict["relationships"], removed_ids
    )

    original_count = len(packages)
    filtered_count = len(filtered_packages)
    removed_count = original_count - filtered_count

    LOGGER.info(
        "Filtered %s packages out of %s (%s remaining)",
        removed_count,
        original_count,
        removed_count,
    )

    return {
        **sbom_dict,
        "packages": filtered_packages,
        "relationships": filtered_relationships,
    }


def filter_hermeto_sbom_by_arch(
    sbom_dict: dict[str, Any], target_arch: str
) -> dict[str, Any]:
    """
    Filter a Hermeto SBOM by architecture, supporting both SPDX and CycloneDX formats.

    Args:
        sbom_dict: The SBOM dictionary
        target_arch: The architecture to filter by (e.g., "x86_64", "aarch64")

    Returns:
        dict[str, Any]: The filtered SBOM dictionary

    Raises:
        ValueError: If the SBOM format is not recognized
    """
    if sbom_dict.get("bomFormat") == "CycloneDX":
        raise NotImplementedError()

    # if this property exists, it's an SPDX type SBOM
    if "spdxVersion" in sbom_dict:
        return _filter_spdx_sbom_by_arch(sbom_dict, target_arch)

    raise ValueError("Unknown SBOM format, cannot filter by architecture")
