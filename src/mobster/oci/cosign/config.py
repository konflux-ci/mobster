"""Configuration for Cosign clients"""

import os
from dataclasses import dataclass
from pathlib import Path


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
