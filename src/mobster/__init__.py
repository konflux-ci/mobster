"""
Mobster root module.
"""

import importlib.metadata


def get_mobster_version() -> str:
    """
    Get the current mobster version as a string using import.metadata.version
    """
    return importlib.metadata.version("mobster")
