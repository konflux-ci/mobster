"""Module for handling OCI artifacts using Cosign"""

from mobster.oci.cosign.anonymous_fetcher import AnonymousFetcher
from mobster.oci.cosign.config import (
    KeylessVerifyConfig,
    SignConfig,
    StaticSignConfig,
    URLSigningConfig,
    VerifyConfig,
)
from mobster.oci.cosign.keyless import KeylessSBOMFetcher, KeylessSigner
from mobster.oci.cosign.protocol import (
    SupportsFetch,
    SupportsProvenanceFetch,
    SupportsSign,
)
from mobster.oci.cosign.static import StaticKeyFetcher, StaticKeySigner


def get_cosign_fetcher(config: VerifyConfig) -> SupportsFetch:
    """
    Instantiates a Cosign fetch client from the provided config.

    Args:
        config: Config for static or Keyless cosign

    Returns:
        Cosign client
    """
    if (
        config.keyless_verify_config
        and config.keyless_verify_config.oidc_issuer
        and config.keyless_verify_config.identity_pattern
    ):
        return KeylessSBOMFetcher(config)
    if config.static_verify_key is not None:
        return StaticKeyFetcher(config)
    raise ValueError(
        "Cannot instantiate full Cosign client from incomplete configuration. "
        "Either support sign and verify keys or run cosign initialize and "
        "provide OIDC token for signing and details about Fulcio and Rekor."
    )


def get_cosign_signer(config: SignConfig) -> SupportsSign:
    """
    Instantiates a Cosign signer from the provided config.

    Args:
        config: Config for static or Keyless cosign

    Returns:
        Cosign signer
    """
    if config.url_config.is_keyless_ready() and config.keyless_token_file is not None:
        return KeylessSigner(config)
    if (
        config.static_sign_config is not None
        and config.static_sign_config.sign_key is not None
    ):
        return StaticKeySigner(config)
    raise ValueError(
        "Cannot instantiate full Cosign client from incomplete configuration. "
        "Either support sign and verify keys or run cosign initialize and "
        "provide OIDC token for signing and details about Fulcio and Rekor."
    )


__all__ = [
    "URLSigningConfig",
    "get_cosign_fetcher",
    "get_cosign_signer",
    "SignConfig",
    "VerifyConfig",
    "StaticSignConfig",
    "SupportsSign",
    "SupportsFetch",
    "SupportsProvenanceFetch",
    "AnonymousFetcher",
    "KeylessSBOMFetcher",
    "KeylessSigner",
    "KeylessVerifyConfig",
    "StaticKeyFetcher",
    "StaticKeySigner",
]
