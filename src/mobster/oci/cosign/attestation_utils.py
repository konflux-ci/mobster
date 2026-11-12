"""Module for functions related to attestations"""

import hashlib
import json
import logging
from base64 import b64decode
from datetime import datetime, timezone
from typing import Literal

from mobster.image import Image
from mobster.oci.artifact import (
    BOM,
    SLSAProvenance,
    get_payload_from_attestation_bytes,
)
from mobster.sbom.detect import BOMFormat

logger = logging.getLogger(__name__)


def get_sbom_from_attestation_bytes(
    attestation_bytes: bytes,
    image: Image,
    signature_verified: bool = False,
) -> BOM:
    """
    Parse an SBOM from an Attestation bytes.
    Supports both attestations produced by Cosign v2 and v3
    (Cosign Bundles).
    Args:
        attestation_bytes: The raw attestation bytes.
            Must be only a single attestation!
        image: The image.
        signature_verified: True only if the fetcher verified the signature.
    Returns:
        SBOM object from this attestation.
    """
    return BOM(
        json.loads(b64decode(get_payload_from_attestation_bytes(attestation_bytes)))[
            "predicate"
        ],
        hashlib.sha256(attestation_bytes).hexdigest(),
        image,
        signature_verified=signature_verified,
    )


def get_cosign_attestation_type(
    sbom_format: BOMFormat,
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


async def get_latest_provenance_from_bytes(
    attestations_bytes: list[bytes],
) -> SLSAProvenance | None:
    """
    Once attestation is fetched (1 attestation per item in the input list),
    this function selects the latest one.
    Args:
        attestations_bytes: List of raw attestations.

    Returns:
        Provenance if found, None otherwise.
    """
    provenances: list[SLSAProvenance] = []

    for raw_attestation in attestations_bytes:
        provenances.append(SLSAProvenance.parse(raw_attestation))

    if len(provenances) == 0:
        return None

    # sort the provenances to ensure we attempt to use the latest one
    if any(p.build_finished_on is None for p in provenances):
        logger.warning(
            "Some fetched provenances are missing build_finished_on information. "
            "datetime.min will be used as fallback for sorting."
        )

    def key_by_build_finished_on(prov: SLSAProvenance) -> datetime:
        if prov.build_finished_on is not None:
            return prov.build_finished_on
        return datetime.min.replace(tzinfo=timezone.utc)

    return sorted(provenances, key=key_by_build_finished_on, reverse=True)[0]
