"""
Module containing classes for OCI artifact parsing.
"""

import base64
import datetime
import hashlib
import json
import logging
from enum import Enum
from typing import Any

import dateutil.parser

from mobster.error import SBOMError
from mobster.image import Image

logger = logging.getLogger(__name__)


class Provenance02:
    """
    Object containing the data of a provenance attestation.

    Attributes:
        predicate (dict): The attestation predicate.
    """

    predicate_type = "https://slsa.dev/provenance/v0.2"

    def __init__(self, predicate: dict[str, Any]) -> None:
        self.predicate = predicate

    @staticmethod
    def from_cosign_output(raw: bytes) -> "Provenance02":
        """
        Create a Provenance02 object from a line of raw "cosign
        verify-attestation" output.
        """
        encoded = json.loads(raw)
        att = json.loads(base64.b64decode(encoded["payload"]))
        if (pt := att.get("predicateType")) != Provenance02.predicate_type:
            raise ValueError(
                f"Cannot parse predicateType {pt}. "
                f"Expected {Provenance02.predicate_type}"
            )

        predicate = att.get("predicate", {})
        return Provenance02(predicate)

    @property
    def build_finished_on(self) -> datetime.datetime:
        """
        Return datetime of the build being finished.
        If it's not available, fallback to datetime.min.
        """
        finished_on: str | None = self.predicate.get("metadata", {}).get(
            "buildFinishedOn"
        )
        if finished_on:
            return dateutil.parser.isoparse(finished_on)

        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

    def get_sbom_digest(self, image: Image) -> str:
        """
        Find the SBOM_BLOB_URL value in the provenance for the supplied image.
        """
        sbom_blob_urls: dict[str, str] = {}
        tasks = self.predicate.get("buildConfig", {}).get("tasks", [])
        for task in tasks:
            curr_digest, sbom_url = "", ""
            for result in task.get("results", []):
                if result.get("name") == "SBOM_BLOB_URL":
                    sbom_url = result.get("value")
                if result.get("name") == "IMAGE_DIGEST":
                    curr_digest = result.get("value")
            if not all([curr_digest, sbom_url]):
                continue
            sbom_blob_urls[curr_digest] = sbom_url

        blob_url = sbom_blob_urls.get(image.digest)
        if blob_url is None:
            raise SBOMError(f"No SBOM_BLOB_URL found in attestation for image {image}.")

        return blob_url.split("@", 1)[1]


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


class SBOM:
    """
    Object representing an SBOM for an image.
    """

    def __init__(self, doc: dict[Any, Any], digest: str, reference: str) -> None:
        """
        An SBOM downloaded using cosign.

        Attributes:
            doc (dict): The parsed SBOM dictionary
            digest (str): SHA256 digest of the raw SBOM data
            reference (str): Reference of the image the SBOM was attached to
        """
        self.doc = doc
        self.digest = digest
        self.reference = reference

    @property
    def format(self) -> SBOMFormat:
        """
        Return the format of the SBOM document.
        """
        if "bomFormat" in self.doc:
            raw = self.doc.get("specVersion")
            if raw is None:
                raise SBOMError("SBOM is missing specVersion field.")

            try:
                spec = SBOMFormat(raw)
            except ValueError:
                raise SBOMError(f"CDX spec {raw} not recognized.") from None

            return spec

        raw = self.doc.get("spdxVersion")
        if raw is None:
            raise SBOMError("SBOM is missing spdxVersion field.")

        try:
            spec = SBOMFormat(raw)
        except ValueError:
            raise SBOMError(f"SPDX spec {raw} not recognized.") from None

        return spec

    @staticmethod
    def from_cosign_output(raw: bytes, reference: str) -> "SBOM":
        """
        Create an SBOM object from a line of raw "cosign download sbom" output.
        """
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as err:
            raise SBOMError("Could not decode SBOM.") from err

        hexdigest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return SBOM(doc, hexdigest, reference)
