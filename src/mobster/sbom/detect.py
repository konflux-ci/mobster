"""Module for SBOM format detection."""

from enum import Enum
from typing import Any

from mobster.error import SBOMError


class SBOMFormat(Enum):
    """
    Enumeration of all SBOM formats supported for updates.
    """

    SPDX_2_0 = "SPDX-2.0"
    SPDX_2_1 = "SPDX-2.1"
    SPDX_2_2 = "SPDX-2.2"
    SPDX_2_2_1 = "SPDX-2.2.1"
    SPDX_2_2_2 = "SPDX-2.2.2"
    SPDX_2_3 = "SPDX-2.3"
    CDX_V1_4 = "1.4"
    CDX_V1_5 = "1.5"
    CDX_V1_6 = "1.6"

    def is_spdx2(self) -> bool:
        """
        Is this format SPDX of version 2.X?

        Returns:
            True if this is SPDX 2.X, False otherwise
        """
        return self.value.startswith("SPDX-2")


def detect_sbom_format(sbom: dict[str, Any]) -> SBOMFormat:
    """
    Return the format of the SBOM document.

    Args:
        sbom: The dictionary to detect.
    Returns:
        The format of the SBOM document.
    """
    if "bomFormat" in sbom:
        raw = sbom.get("specVersion")
        if raw is None:
            raise SBOMError("SBOM is missing specVersion field.")

        try:
            spec = SBOMFormat(raw)
        except ValueError:
            raise SBOMError(f"CDX spec {raw} not recognized.") from None

        return spec

    raw = sbom.get("spdxVersion")
    if raw is None:
        raise SBOMError("SBOM is missing spdxVersion field.")

    try:
        spec = SBOMFormat(raw)
    except ValueError:
        raise SBOMError(f"SPDX spec {raw} not recognized.") from None

    return spec
