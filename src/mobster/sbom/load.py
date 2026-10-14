"""
Utilities for loading SBOMs into object-oriented representations
"""

import logging
from pathlib import Path
from typing import Any

from spdx_tools.spdx.model.document import Document

from mobster.sbom.cyclonedx_wrapper import CycloneDX1BomWrapper
from mobster.sbom.detect import detect_sbom_format
from mobster.sbom.spdx import normalize_and_load_sbom
from mobster.utils import load_file_to_dict

LOGGER = logging.getLogger(__name__)


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
