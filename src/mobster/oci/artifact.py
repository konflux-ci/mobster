"""
Module containing classes for OCI artifact parsing.
"""

import base64
import binascii
import datetime
import hashlib
import json
import logging
from enum import Enum
from typing import Any

import dateutil.parser

from mobster.error import SBOMError
from mobster.image import parse_image_reference

logger = logging.getLogger(__name__)


class SLSAParsingError(Exception):
    """
    Exception raised when parsing SLSA provenance data fails.
    """


class SLSAProvenance:
    """
    Class for parsing and accessing SLSA provenance data.

    Parses SLSA provenance payloads and provides access to build metadata
    and SBOM digest mappings for container images.
    """

    def __init__(
        self, build_finished_on: datetime.datetime, sbom_digests: dict[str, str]
    ) -> None:
        self._build_finished_on = build_finished_on
        self._sbom_digests: dict[str, str] = sbom_digests

    @staticmethod
    def parse(raw: bytes) -> "SLSAProvenance":
        """
        Parse a raw cosign attestation payload into an SLSAProvenance.

        Args:
            raw: Raw bytes from cosign verify-attestation output.

        Raises:
            SLSAParsingError: If the SLSA version is not supported, the
                statement is missing a predicateType field, or byproduct
                content cannot be decoded.
        """
        encoded = json.loads(raw)
        statement = json.loads(base64.b64decode(encoded["payload"]))

        predicate_type = statement.get("predicateType")
        if predicate_type is None:
            raise SLSAParsingError(
                'Statement is missing required "predicateType" field'
            )

        predicate = statement.get("predicate")

        if predicate_type == "https://slsa.dev/provenance/v0.2":
            return SLSAProvenance._parse_v02(predicate)
        if predicate_type == "https://slsa.dev/provenance/v1":
            return SLSAProvenance._parse_v1(predicate)

        raise SLSAParsingError(
            f"Cannot parse SLSA provenance with predicateType {predicate_type}."
        )

    @staticmethod
    def _parse_v02(predicate: Any) -> "SLSAProvenance":
        # parse build_finished_on

        finished_on: str | None = predicate.get("metadata", {}).get("buildFinishedOn")
        if finished_on:
            build_finished_on = dateutil.parser.isoparse(finished_on)
        else:
            build_finished_on = datetime.datetime.min.replace(
                tzinfo=datetime.timezone.utc
            )

        # map image digests to sbom blob digests
        sbom_blob_urls: dict[str, str] = {}
        tasks = predicate.get("buildConfig", {}).get("tasks", [])
        for task in tasks:
            curr_digest, sbom_url = "", ""
            for result in task.get("results", []):
                if result.get("name") == "SBOM_BLOB_URL":
                    sbom_url = result.get("value")
                if result.get("name") == "IMAGE_DIGEST":
                    curr_digest = result.get("value")
            if not all([curr_digest, sbom_url]):
                continue

            sbom_blob_urls[curr_digest] = sbom_url.split("@", 1)[1]

        return SLSAProvenance(build_finished_on, sbom_blob_urls)

    @staticmethod
    def _parse_v1(predicate: Any) -> "SLSAProvenance":
        finished_on: str | None = (
            predicate.get("runDetails", {}).get("metadata", {}).get("finishedOn")
        )
        if finished_on:
            build_finished_on = dateutil.parser.isoparse(finished_on)
        else:
            build_finished_on = datetime.datetime.min.replace(
                tzinfo=datetime.timezone.utc
            )

        image_digests: dict[str, str] = {}
        sbom_digests: dict[str, str] = {}
        byproducts = predicate.get("runDetails", {}).get("byproducts", [])

        for byproduct in byproducts:
            name = byproduct.get("name", "")
            if name not in (
                "taskRunResults/IMAGE_REF",
                "taskRunResults/SBOM_BLOB_URL",
            ):
                continue

            content = byproduct.get("content")
            if content is None:
                raise SLSAParsingError(
                    f'Byproduct with name {name} is missing "content" field'
                )

            try:
                decoded = json.loads(base64.b64decode(content))
            except (binascii.Error, json.JSONDecodeError) as err:
                raise SLSAParsingError(
                    f"Failed to decode {name} content: {err}"
                ) from err

            if not isinstance(decoded, str):
                raise SLSAParsingError(
                    f"Expected string content for {name}, got {type(decoded).__name__}"
                )

            repository, digest = parse_image_reference(decoded)
            if name == "taskRunResults/IMAGE_REF":
                image_digests.setdefault(repository, digest)
            elif name == "taskRunResults/SBOM_BLOB_URL":
                sbom_digests[repository] = digest

        sbom_blob_urls = {
            image_digests[repo]: sbom_digest
            for repo, sbom_digest in sbom_digests.items()
            if repo in image_digests
        }

        return SLSAProvenance(build_finished_on, sbom_blob_urls)

    @property
    def build_finished_on(self) -> datetime.datetime:
        """
        Get the timestamp when the build finished.

        Returns:
            The build completion timestamp, or datetime.min with UTC timezone
            if the timestamp was not available in the provenance data.
        """
        return self._build_finished_on

    def sbom_digest(self, image_digest: str) -> str | None:
        """
        Get the SBOM digest for a given image digest.

        Args:
            image_digest: SHA256 digest of the container image

        Returns:
            The corresponding SBOM digest, or None if not found in the
            provenance data.
        """
        return self._sbom_digests.get(image_digest)


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


class SBOM:
    """
    Object representing an SBOM for an image.
    """

    def __init__(self, doc: dict[Any, Any], digest: str, reference: str) -> None:
        """
        An SBOM downloaded using cosign.

        Args:
            doc: The parsed SBOM dictionary
            digest: SHA256 digest of the raw SBOM data
            reference: Reference of the image the SBOM was attached to
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
        Create an SBOM object from raw cosign download sbom output.

        Args:
            raw: Raw bytes from cosign download sbom command
            reference: Image reference string
        """
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as err:
            raise SBOMError("Could not decode SBOM.") from err

        hexdigest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return SBOM(doc, hexdigest, reference)
