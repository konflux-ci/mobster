"""Module for handling OCI artifacts using Cosign"""

from mobster.oci.cosign.anonymous_fetcher import AnonymousFetcher
from mobster.oci.cosign.config import (
    KeylessSignConfig,
    KeylessVerifyConfig,
    RekorConfig,
    SignConfig,
    StaticSignConfig,
    VerifyConfig,
)
from mobster.oci.cosign.keyless import KeylessSBOMFetcher, KeylessSigner
from mobster.oci.cosign.protocol import SupportsFetch, SupportsSign
from mobster.oci.cosign.static import StaticKeyFetcher, StaticKeySigner


def get_cosign_fetcher(config: VerifyConfig) -> SupportsFetch:
    """
    Instantiates a Cosign fetch client from the provided config.
    Args:
        config: Config for static or Keyless cosign
    Returns:
        Cosign client
    """
    if config.keyless_verify_config is not None and config.rekor_config is not None:
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
        config:  Config for static or Keyless cosign
    Returns: Cosign signer
    """
    if config.keyless_config is not None and config.rekor_config is not None:
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
    "get_cosign_fetcher",
    "get_cosign_signer",
    "SignConfig",
    "VerifyConfig",
    "KeylessVerifyConfig",
    "StaticSignConfig",
    "KeylessSignConfig",
    "RekorConfig",
    "SupportsSign",
    "SupportsFetch",
    "AnonymousFetcher",
    "KeylessSBOMFetcher",
    "KeylessSigner",
    "StaticKeyFetcher",
    "StaticKeySigner",
]
