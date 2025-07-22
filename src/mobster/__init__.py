"""
Mobster root module.
"""

import importlib.metadata


def get_mobster_version() -> str:
    """
    Get the current mobster version as a string using import.metadata.version
    """
    return importlib.metadata.version("mobster")


def get_mobster_tool_string() -> str:
    """
    Get the string representation of the current mobster tool.
    """
    return f"Tool: Mobster-{get_mobster_version()}"
