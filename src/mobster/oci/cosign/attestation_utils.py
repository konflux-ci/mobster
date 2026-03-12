"""Module for functions related to attestations"""

import hashlib
import json
from base64 import b64decode
from typing import Literal

from mobster.oci.artifact import SBOM, SBOMFormat


def get_sbom_from_attestation_bytes(
    attestation_bytes: bytes, image_reference: str
) -> SBOM:
    """
    Parse an SBOM from an Attestation bytes.
    Args:
        attestation_bytes: The raw attestation bytes.
            Must be only a single attestation!
        image_reference: The image reference.
    Returns:
        SBOM object from this attestation.
    """
    return SBOM(
        json.loads(b64decode(json.loads(attestation_bytes)["payload"]))["predicate"],
        hashlib.sha256(attestation_bytes).hexdigest(),
        image_reference,
    )


def get_cosign_attestation_type(
    sbom_format: SBOMFormat,
) -> Literal["spdxjson", "cyclonedx"]:
    """
    Get the cosign-compatible string determining the SBOM type.
    Translates SBOMFormat to a literal string compatible with cosign CLI.

    Args:
        sbom_format: The SBOM format to translate

    Returns:
        The string literal which is compatible with cosign CLI
    """
    # Translate SPDX format to a cosign-supported version. See
    # https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md#options
    if sbom_format.is_spdx2():
        return "spdxjson"
    return "cyclonedx"
