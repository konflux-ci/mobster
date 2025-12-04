"""Merging utility for model cards"""

from typing import Any


def _merge_union(a: list[Any], b: list[Any]) -> list[Any]:
    """Append items from b not already in a."""
    return a + [p for p in b if p not in a]


def _prefer_a(a: Any, _b: Any) -> Any:
    return a


def _merge_dicts(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """b | a so that a's keys win."""
    return b | a


def _merge_union_by_key(key: str) -> Any:
    """Deduplicate a list of objects by a given identity key, preferring a's value."""

    def merge_by_key(
        a: list[dict[str, Any]], b: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        existing_keys = {item[key] for item in a if key in item}
        return a + [item for item in b if item.get(key) not in existing_keys]

    return merge_by_key
