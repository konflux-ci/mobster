"""
Utilities for loading SBOMs into object-oriented representations
"""

import json
import logging
from enum import Enum
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from spdx_tools.spdx.model.document import Document

from mobster.error import SBOMError
from mobster.sbom.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.spdx import normalize_and_load_sbom

LOGGER = logging.getLogger(__name__)


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


def load_dict_to_sbom(
    sbom: dict[str, Any], append_mobster: bool = False
) -> Document | CycloneDX1BomWrapper:
    """
    Loads a dictionary into an SBOM object.
    Autodetects SBOM formats.

    Args:
        sbom: The dictionary to load.
        append_mobster: Should Mobster append itself
            to the creator tools?

    Returns:
        The loaded SBOM object.
    """
    sbom_format = detect_sbom_format(sbom)
    if sbom_format.is_spdx2():
        return normalize_and_load_sbom(sbom, append_mobster)
    return CycloneDX1BomWrapper.from_dict(sbom, append_mobster)


def load_file_to_dict(sbom_file: Path) -> dict[str, Any]:
    """
    Loads a file into a dictionary object.
    Args:
        sbom_file: The path to the SBOM file.

    Returns:
        The loaded dictionary.
    """
    with open(sbom_file, encoding="utf-8") as in_stream:
        try:
            contents = in_stream.read()
            return json.loads(contents)  # type: ignore[no-any-return]
        except JSONDecodeError:
            LOGGER.critical(
                "Expected a JSON SBOM. Found different file contents! "
                "Logging first 200 chars of the file."
            )
            LOGGER.critical(contents[:200])
            raise


def load_file_to_sbom(
    sbom_file: Path, append_mobster: bool = False
) -> Document | CycloneDX1BomWrapper:
    """
    Loads a file into a SBOM object.
    Args:
        sbom_file:  The path to the SBOM file.
        append_mobster: Should Mobster append itself
            to the creator tools?

    Returns:
        The loaded SBOM object.
    """
    dict_sbom = load_file_to_dict(sbom_file)
    return load_dict_to_sbom(dict_sbom, append_mobster)
