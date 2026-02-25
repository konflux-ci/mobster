"""
This module contains the Cosign protocol and the real Cosign implementation.
The protocol is used mainly for testing. The tests inject a testing cosign
client implementing the Cosign protocol.
"""

import logging
import os
import typing
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mobster.image import Image
from mobster.oci.artifact import SBOM, Provenance02, SBOMFormat

logger = logging.getLogger(__name__)


@dataclass
class RekorConfig:
    """
    Rekor (TLOG) configuration object definition.
    """

    rekor_url: str
    rekor_key: Path | None = None


@dataclass
class StaticSignConfig:
    """
    Static (using keys) cosign configuration
    Attributes:
        sign_key: path or URL to the signing key for SBOM attesting
        sign_password: password used for encrypting the signing key
    """

    sign_key: os.PathLike[str]
    sign_password: bytes = b""


@dataclass
class KeylessSignConfig:
    """
    Keyless (using OIDC) cosign configuration for signing
    Attributes:
        fulcio_url: URL to the used certificate authority for keyless signing
        token_file: path to OIDC token used for keyless authentication
    """

    fulcio_url: str
    token_file: Path


@dataclass
class KeylessVerifyConfig:
    """
    Keyless (using OIDC) cosign configuration for verification
    Attributes:
        issuer_pattern: RegEx pattern for validating token issuer, used for
            keyless attested SBOM verification
        identity_pattern: RegEx pattern for validating token identity, used for
            keyless attested SBOM verification
    """

    issuer_pattern: str
    identity_pattern: str


@dataclass
class SignConfig:
    """
    Configuration of Cosign keys for signing.
    Attributes:
        static_sign_config: configuration for static signing
        rekor_config: rekor URL and optionally key,
            used for static and keyless attesting
        keyless_config: configuration for keyless signing
    """

    static_sign_config: StaticSignConfig | None = None
    rekor_config: RekorConfig | None = None
    keyless_config: KeylessSignConfig | None = None


@dataclass
class VerifyConfig:
    """
    Configuration of Cosign keys for verification.

    Attributes:
        static_verify_key: verification static key path
        rekor_config: rekor URL and optionally key,
            used for static and keyless attesting
        keyless_verify_config: keyless verification configuration
    """

    static_verify_key: os.PathLike[str] | None = None
    rekor_config: RekorConfig | None = None
    keyless_verify_config: KeylessVerifyConfig | None = None


def get_cosign_attestation_type(
    sbom_format: SBOMFormat,
) -> Literal["spdxjson", "cyclonedx"]:
    """
    Get the cosign-compatible string determining the SBOM type.
    Translates SBOMFormat to a literal string.
    Args:
        sbom_format: The SBOM format to be converted into a string

    Returns:
        The string literal which is compatible with cosign cli.
    """
    # Translate SPDX format to a cosign-supported version. See
    # https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md#options
    if sbom_format.is_spdx2():
        return "spdxjson"
    return "cyclonedx"


class SupportsFetch(typing.Protocol):  # pragma: nocover
    """
    Definition of a Cosign fetch protocol.
    """

    async def fetch_sbom(self, image: Image) -> SBOM:
        """
        Fetch the attached SBOM for an image.
        """
        raise NotImplementedError()

    async def fetch_latest_provenance(self, image: Image) -> Provenance02:
        """
        Fetch the latest provenance for an image.
        """
        raise NotImplementedError()


class SupportsSign(typing.Protocol):
    """
    Definition of a Cosign sign protocol.
    """

    # pylint: disable=too-few-public-methods

    async def attest_sbom(
        self,
        sbom_path: Path,
        image_ref: str,
        sbom_format: SBOMFormat,
    ) -> None:
        """
        Use cosign to attach an SBOM to the registry. This is the new
        way of attaching an SBOM to an image.
        Args:
            sbom_path: The path to the SBOM file
            image_ref: The reference of the image
            sbom_format: The format of the SBOM to attest

        Returns:
            None
        """
        raise NotImplementedError()
