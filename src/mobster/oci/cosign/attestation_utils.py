"""Module for functions related to attestations"""

from typing import Literal

from mobster.oci.artifact import SBOMFormat


def get_cosign_attestation_type(
    sbom_format: SBOMFormat,
) -> Literal["spdxjson", "cyclonedx"]:
    """
    Get the cosign-compatible string determining the SBOM type.
    Translates SBOMFormat to a literal string.
    The string literal which is compatible with cosign cli.
    """
    # Translate SPDX format to a cosign-supported version. See
    # https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md#options
    if sbom_format.is_spdx2():
        return "spdxjson"
    return "cyclonedx"
