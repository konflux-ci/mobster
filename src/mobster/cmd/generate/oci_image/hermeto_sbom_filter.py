"""A module for filtering an SBOM produced by Hermeto by architecture."""

import logging
from typing import Any

LOGGER = logging.getLogger(__name__)


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
        raise NotImplementedError()

    raise ValueError("Unknown SBOM format, cannot filter by architecture")
