"""Module for choosing correct cosign client"""

from mobster.oci.cosign import (
    CosignSignConfig,
    CosignVerifyConfig,
    SupportsFetch,
    SupportsSign,
)
from mobster.oci.cosign.keyless_cosign import KeylessCosign, KeylessSigner
from mobster.oci.cosign.static_cosign import CosignClient, CosignSigner


def get_cosign_fetcher(config: CosignVerifyConfig) -> SupportsFetch:
    """
    Instantiates a Cosign fetch client from the provided config.
    Args:
        config: Config for static or Keyless cosign
    Returns:
        Cosign client
    """
    if config.keyless_verify_config is not None and config.rekor_config is not None:
        return KeylessCosign(config)
    if config.static_verify_key is not None:
        return CosignClient(config)
    raise ValueError(
        "Cannot instantiate full Cosign client from incomplete configuration. "
        "Either support sign and verify keys or run cosign initialize and "
        "provide OIDC token for signing and details about Fulcio and Rekor."
    )


def get_cosign_signer(config: CosignSignConfig) -> SupportsSign:
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
        return CosignSigner(config)
    raise ValueError(
        "Cannot instantiate full Cosign client from incomplete configuration. "
        "Either support sign and verify keys or run cosign initialize and "
        "provide OIDC token for signing and details about Fulcio and Rekor."
    )
