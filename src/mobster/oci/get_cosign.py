"""Module for choosing correct cosign client"""

import os

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


def use_keyless() -> bool:
    """
    Check if keyless Cosign should be used.
    Returns:
        True if the environment requires keyless
        cosign protocol. False otherwise.
    """
    if os.getenv("COSIGN_METHOD", "STATIC") == "KEYLESS":
        return True
    return False


def get_unauthenticated_cosign() -> Cosign:
    """
    Gets unauthenticated cosign for fetching purposes only.
    Returns:

    """
    if use_keyless():
        return KeylessCosign(KeylessConfig())
    return CosignClient(CosignConfig())
