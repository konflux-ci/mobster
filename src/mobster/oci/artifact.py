"""
Module containing classes for OCI artifact parsing.
"""

import base64
import binascii
import datetime
import hashlib
import json
import logging
from typing import Any

import dateutil.parser

from mobster.error import SBOMError
from mobster.sbom.detect import SBOMFormat, detect_sbom_format

logger = logging.getLogger(__name__)


def get_payload_from_attestation_bytes(attestation_bytes: bytes) -> str:
    """Returns the B64-encoded payload of this attestation."""
    loaded_attestation_dict = json.loads(attestation_bytes)
    if (
        loaded_attestation_dict.get("mediaType")
        == "application/vnd.dev.sigstore.bundle.v0.3+json"
    ):
        return loaded_attestation_dict["dsseEnvelope"]["payload"]  # type: ignore[no-any-return]
    return loaded_attestation_dict["payload"]  # type: ignore[no-any-return]


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
        self, build_finished_on: datetime.datetime | None, sbom_digests: dict[str, str]
    ) -> None:
        self._build_finished_on = build_finished_on
        self._sbom_digests: dict[str, str] = sbom_digests

    @staticmethod
    def parse(attestation: bytes) -> "SLSAProvenance":
        """
        Parse a raw in-toto attestation into an SLSAProvenance.
        https://github.com/in-toto/attestation/blob/main/spec/README.md#in-toto-attestation-framework-spec

        Args:
            attestation: Bytes containing data of an in-toto attestation.
                E.g. a line of output from "cosign verify-attestation".

        Raises:
            SLSAParsingError: If the SLSA version is not supported, the
                statement is missing a predicateType field, or some required
                provenance content cannot be decoded.
        """
        statement = json.loads(
            base64.b64decode(get_payload_from_attestation_bytes(attestation))
        )

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
    def _parse_results_to_sbom_digests(
        results_to_parse: list[dict[str, str]],
    ) -> dict[str, str]:
        """
        Parses taskRun results to extract data for verification.
        Args:
            results_to_parse: Iterable of task results.

        Returns:
            Mapped Image digests to SBOM digests.
        """
        sbom_blob_url, image_digest = "", ""
        sbom_urls: dict[str, str] = {}
        for result in results_to_parse:
            match result.get("name"):
                case "SBOM_BLOB_URL":
                    sbom_blob_url = result.get("value", "")
                case "IMAGE_DIGEST":
                    image_digest = result.get("value", "")
            if all([sbom_blob_url, image_digest]):
                sbom_digest = sbom_blob_url.split("@", 1)[1]
                sbom_urls[image_digest] = sbom_digest
        return sbom_urls

    @staticmethod
    def _parse_v02(predicate: Any) -> "SLSAProvenance":
        """
        Parse an SLSA provenance v0.2 from an in-toto attestation's predicate
        field.
        https://github.com/in-toto/attestation/blob/main/spec/README.md#in-toto-attestation-framework-spec

        Spec of the provenance can be found in https://slsa.dev/provenance/v0.2

        Args:
            predicate: Contents of the "predicate" field of the in-toto
                attestation's statement parsed into a dictionary object.

        Returns:
            An SLSAProvenance object populated with data from the predicate.
        """
        # parse build_finished_on

        finished_on: str | None = predicate.get("metadata", {}).get("buildFinishedOn")
        if finished_on:
            build_finished_on = dateutil.parser.isoparse(finished_on)
        else:
            build_finished_on = None

        # map image digests to sbom blob digests
        sbom_digests: dict[str, str] = {}
        tasks = predicate.get("buildConfig", {}).get("tasks", [])
        for task in tasks:
            sbom_digests.update(
                SLSAProvenance._parse_results_to_sbom_digests(task.get("results", []))
            )

        return SLSAProvenance(build_finished_on, sbom_digests)

    @staticmethod
    def _parse_v1(predicate: Any) -> "SLSAProvenance":
        """
        Parse an SLSA provenance v1 from an in-toto attestation's predicate
        field.
            https://github.com/in-toto/attestation/blob/main/spec/README.md#in-toto-attestation-framework-spec

        Args:
            predicate: Contents of the "predicate" field of the in-toto
                attestation's statement parsed into a dictionary object.

        Spec of the provenance can be found in https://slsa.dev/provenance/v1

        Returns:
            An SLSAProvenance object populated with data from the predicate.
        """
        finished_on: str | None = (
            predicate.get("runDetails", {}).get("metadata", {}).get("finishedOn")
        )
        if finished_on:
            build_finished_on = dateutil.parser.isoparse(finished_on)
        else:
            build_finished_on = None

        sbom_digests: dict[str, str] = {}

        for task_run in predicate.get("buildDefinition", {}).get(
            "resolvedDependencies", []
        ):
            content = task_run.get("content")
            task_uri = task_run.get("uri")
            if not content:
                continue
            try:
                decoded = json.loads(base64.b64decode(content))
            except (binascii.Error, json.JSONDecodeError) as err:
                raise SLSAParsingError(
                    f"Failed to decode {task_uri} content: {err}"
                ) from err
            sbom_digests.update(
                SLSAProvenance._parse_results_to_sbom_digests(
                    decoded.get("status", {}).get("results", [])
                )
            )

        return SLSAProvenance(build_finished_on, sbom_digests)

    @property
    def build_finished_on(self) -> datetime.datetime | None:
        """
        Get the timestamp when the build finished.

        Returns:
            The build completion timestamp, or None if the timestamp was not
            available in the provenance data.
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
        return detect_sbom_format(self.doc)

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
