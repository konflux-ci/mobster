"""Module for choosing correct cosign client"""

from mobster.oci.cosign import Cosign, CosignClient, CosignConfig
from mobster.oci.keyless_cosign import KeylessConfig, KeylessCosign


def get_cosign(config: CosignConfig | KeylessConfig) -> Cosign:
    """
    Instantiates a Cosign client from the provided config.
    Args:
        config: Config for static or Keyless cosign
    Returns:
        Cosign client
    """
    if isinstance(config, CosignConfig):
        return CosignClient(config)
    return KeylessCosign(config)
