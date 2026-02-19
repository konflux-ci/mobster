"""Module for choosing correct cosign client"""

from mobster.oci.cosign import Cosign, CosignConfig
from mobster.oci.cosign.keyless_cosign import KeylessCosign
from mobster.oci.cosign.static_cosign import CosignClient


def get_cosign(config: CosignConfig) -> Cosign:
    """
    Instantiates a Cosign client from the provided config.
    Args:
        config: Config for static or Keyless cosign
    Returns:
        Cosign client
    """
    if (
        config.keyless_config is not None
        and config.rekor_config is not None
        and KeylessCosign.check_tuf()
    ):
        return KeylessCosign(config)
    if (
        config.static_sign_config is not None
        and config.static_sign_config.verify_key is not None
        and config.static_sign_config.sign_key is not None
    ):
        return CosignClient(config)
    raise ValueError(
        "Cannot instantiate full Cosign client from incomplete configuration. "
        "Either support sign and verify keys or run cosign initialize and "
        "provide OIDC token for signing and details about Fulcio and Rekor."
    )
