"""
Module containing classes for OCI artifact parsing.
"""

import hashlib
import json
from typing import Optional, Any
import base64
import datetime

import dateutil.parser

from mobster.error import SBOMError
from mobster.image import Image
from mobster.logging import get_mobster_logger


logger = get_mobster_logger()


class Provenance02:
    """
    Object containing the data of an provenance attestation.
    """

    predicate_type = "https://slsa.dev/provenance/v0.2"

    def __init__(self, predicate: Any) -> None:
        self.predicate = predicate

    @staticmethod
    def from_cosign_output(raw: bytes) -> "Provenance02":
        encoded = json.loads(raw)
        att = json.loads(base64.b64decode(encoded["payload"]))
        if (pt := att.get("predicateType")) != Provenance02.predicate_type:
            raise ValueError(
                f"Cannot parse predicateType {pt}. Expected {Provenance02.predicate_type}"
            )

        predicate = att.get("predicate", {})
        return Provenance02(predicate)

    @property
    def build_finished_on(self) -> datetime.datetime:
        """
        Return datetime of the build being finished.
        If it's not available, fallback to datetime.min.
        """
        if self.predicate is None:
            raise ValueError("Cannot get build time from uninitialized provenance.")

        finished_on: Optional[str] = self.predicate.get("metadata", {}).get(
            "buildFinishedOn"
        )
        if finished_on:
            return dateutil.parser.isoparse(finished_on)

        return datetime.datetime.min

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


class SBOM:
    def __init__(self, doc: dict[Any, Any], digest: str) -> None:
        """
        An SBOM downloaded using cosign.

        Attributes:
            doc (dict): The parsed SBOM dictionary
            digest (str): SHA256 digest of the raw SBOM data
        """
        self.doc = doc
        self.digest = digest

    @staticmethod
    async def from_cosign_output(raw: bytes) -> "SBOM":
        """
        Create an SBOM object from a line of raw "cosign download sbom" output.
        """
        doc = json.loads(raw)
        hexdigest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return SBOM(doc, hexdigest)
