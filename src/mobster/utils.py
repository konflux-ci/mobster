"""A place for utility functions used across the application."""

import re


def normalize_file_name(current_name: str) -> str:
    """
    Normalize a file name by replacing invalid characters with underscores.

    Args:
        current_name (str): The original file name.

    Returns:
        str: The normalized file name.
    """
    return re.sub(r'[<>:"/\\|?*]', "_", current_name)
